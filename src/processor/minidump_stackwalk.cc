// Copyright 2010 Google LLC
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// minidump_stackwalk.cc: Process a minidump with MinidumpProcessor, printing
// the results, including stack traces.
//
// Author: Mark Mentovai

#ifdef HAVE_CONFIG_H
#include <config.h>  // Must come first
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <limits>
#include <string>
#include <vector>

#include <chrono>
#include <iostream>
#include <print>
#include <ranges>
#include <regex>
#include "common/path_helper.h"
#include "common/scoped_ptr.h"
#include "common/using_std_string.h"
#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/stack_frame.h"
#include "processor/logging.h"
#include "processor/simple_symbol_supplier.h"
#include "processor/stackwalk_common.h"

namespace {

struct Options {
  bool machine_readable;
  bool output_stack_contents;
  bool output_requesting_thread_only;
  bool brief;

  string minidump_file;
  std::vector<string> symbol_paths;
};

using google_breakpad::BasicSourceLineResolver;
using google_breakpad::Minidump;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpProcessor;
using google_breakpad::MinidumpThreadList;
using google_breakpad::ProcessState;
using google_breakpad::scoped_ptr;
using google_breakpad::SimpleSymbolSupplier;

static void DumpRawStream(Minidump* minidump,
                          uint32_t stream_type,
                          const char* stream_name,
                          int* errors) {
  uint32_t length = 0;
  if (!minidump->SeekToStreamType(stream_type, &length)) {
    return;
  }

  printf("Stream %s:\n", stream_name);

  if (length == 0) {
    printf("\n");
    return;
  }
  std::vector<char> contents(length);
  if (!minidump->ReadBytes(&contents[0], length)) {
    ++*errors;
    BPLOG(ERROR) << "minidump.ReadBytes failed";
    return;
  }
  size_t current_offset = 0;
  while (current_offset < length) {
    size_t remaining = length - current_offset;
    // Printf requires an int and direct casting from size_t results
    // in compatibility warnings.
    uint32_t int_remaining = remaining;
    printf("%.*s", int_remaining, &contents[current_offset]);
    char* next_null = reinterpret_cast<char*>(
        memchr(&contents[current_offset], 0, remaining));
    if (next_null == NULL)
      break;
    printf("\\0\n");
    size_t null_offset = next_null - &contents[0];
    current_offset = null_offset + 1;
  }
  printf("\n\n");
}

enum class encoding_type : uint8_t {
  pad = 0,
  string,
  boolean,
  uint8,
  int8,
  uint16,
  int16,
  uint32,
  int32,
  uint64,
  int64,
  source_location,
  node_handle,
  cached_string,
  binary,
  invalid = 255,  //
};
enum class level_e { error, warn, info, debug, trace };

// Processes |options.minidump_file| using MinidumpProcessor.
// |options.symbol_path|, if non-empty, is the base directory of a
// symbol storage area, laid out in the format required by
// SimpleSymbolSupplier.  If such a storage area is specified, it is
// made available for use by the MinidumpProcessor.
//
// Returns the value of MinidumpProcessor::Process.  If processing succeeds,
// prints identifying OS and CPU information from the minidump, crash
// information if the minidump was produced as a result of a crash, and
// call stacks for each thread contained in the minidump.  All information
// is printed to stdout.
bool PrintMinidumpProcess(const Options& options) {
  scoped_ptr<SimpleSymbolSupplier> symbol_supplier;
  if (!options.symbol_paths.empty()) {
    // TODO(mmentovai): check existence of symbol_path if specified?
    symbol_supplier.reset(new SimpleSymbolSupplier(options.symbol_paths));
  }

  BasicSourceLineResolver resolver;
  MinidumpProcessor minidump_processor(symbol_supplier.get(), &resolver);

  // Increase the maximum number of threads and regions.
  MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
  MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());
  // Process the minidump.
  Minidump dump(options.minidump_file);
  if (!dump.Read()) {
    BPLOG(ERROR) << "Minidump " << dump.path() << " could not be read";
    return false;
  }
  ProcessState process_state;
  if (minidump_processor.Process(&dump, &process_state) !=
      google_breakpad::PROCESS_OK) {
    BPLOG(ERROR) << "MinidumpProcessor::Process failed";
    return false;
  }

  if (options.machine_readable) {
    PrintProcessStateMachineReadable(process_state);
  } else if (options.brief) {
    PrintRequestingThreadBrief(process_state);
  } else {
    PrintProcessState(process_state, options.output_stack_contents,
                      options.output_requesting_thread_only, &resolver);

    printf("\n");
    {
      std::map<uint32_t, std::string> locations;
      std::map<uint64_t, std::string> node_handles;
      std::map<uint64_t, std::string> string_cache;
      auto memory_list = dump.GetMemoryList();
      for (size_t i = 0; i < memory_list->region_count(); i++) {
        auto region = memory_list->GetMemoryRegionAtIndex(i);
        uint64_t magic = 0;
        if (!region->GetMemoryAtAddress(region->GetBase(), &magic))
          continue;
        if (magic == 724313520984115534ULL) {
          uint64_t size = 0;
          if (!region->GetMemoryAtAddress(region->GetBase() + 8, &size))
            continue;
          printf("NIE Log: %lu %lu %lu\n", uint64_t(size),
                 uint64_t(region->GetBase()), uint64_t(region->GetSize()));
          uint64_t cursor = region->GetBase() + 16;
          while (cursor < (region->GetBase() + region->GetSize())) {
            uint64_t frame_size = 0;
            if (!region->GetMemoryAtAddress(cursor, &frame_size)) {
              printf("Invalid Read\n");
              break;
            }
            if ((frame_size == 0) || (frame_size % 8) || (frame_size < 24)) {
              printf("Invalid Frame Size %lu\n", frame_size);
              break;
            }
            uint64_t time;
            region->GetMemoryAtAddress(cursor + 8, &time);
            uint64_t address;
            region->GetMemoryAtAddress(cursor + 16, &address);
            google_breakpad::StackFrame frame;
            frame.instruction = address;
            std::string info = std::format("{:#x}", address);
            std::vector<std::string> names;
            std::string level = "????";
            if (minidump_processor.stackwalker->look(frame)) {
              info = frame.function_name;
#define STR1 \
  "(XtlNS([0-9]+_|_14string_literal)ILm[0-9]+EEEtlA[0-9]+_c((Lc[0-9]+E)+)EEE)"
#define STR2 "(XtlS[A-Z0-9]+_tlS[A-Z0-9]_((Lc[0-9]+E)+)EEE)"
#define ALLSTR "(" STR1 "|" STR2 ")"
              auto onlychar = [&](std::string m) {
                std::string ret;
                static std::regex re("Lc([0-9]+)E", std::regex::ECMAScript);
                for (std::smatch sm; regex_search(m, sm, re);)
                  if (sm.size() > 1) {
                    ret += char(std::stoull(sm[1].str()));
                    m = sm.suffix();
                  }
                return ret;
              };
              static std::regex re(
                  "^_ZN3nie11log_messageILNS_7level_eE"
                  "([0-9])E" STR1 "J(" ALLSTR
                  "*)"
                  "EE9singletonE",
                  std::regex::ECMAScript);
              std::smatch match;
              if (std::regex_match(frame.function_name, match, re))
                if (match.size() > 6) {
                  switch (static_cast<level_e>(std::stoull(match[1].str()))) {
                    case level_e::error:
                      level = "eror";
                      break;
                    case level_e::warn:
                      level = "warn";
                      break;
                    case level_e::info:
                      level = "info";
                      break;
                    case level_e::debug:
                      level = "debg";
                      break;
                    case level_e::trace:
                      level = "trac";
                      break;
                  }
                  info = onlychar(match[2].str());
                  static std::regex re2(ALLSTR, std::regex::ECMAScript);
                  auto m = match[6].str();
                  for (std::smatch sm; regex_search(m, sm, re2);)
                    if (sm.size() > 0) {
                      names.push_back(onlychar(sm.str()));
                      m = sm.suffix();
                    }
                }
            }
            std::vector<std::string> datas;
            for (size_t i = 24; i < frame_size;) {
              uint8_t type;
              if (!region->GetMemoryAtAddress(cursor + i, &type))
                break;
              i++;
              if (type != 0) {
                datas.emplace_back();
                switch (static_cast<encoding_type>(type)) {
                  case encoding_type::invalid: {
                    uint32_t len;
                    if (!region->GetMemoryAtAddress(cursor + i, &len))
                      continue;
                    i += 4;
                    if (len < 1024) {
                      for (size_t j = 0; j < len; j++) {
                        uint8_t b;
                        if (!region->GetMemoryAtAddress(cursor + i + j, &b))
                          break;
                        datas.back() += char(b);
                      }
                      i += len;
                    } else
                      break;
                  } break;
                  case encoding_type::string: {
                    datas.back() += "\"";
                    uint32_t len;
                    if (!region->GetMemoryAtAddress(cursor + i, &len))
                      continue;
                    i += 4;
                    if (len < 1024) {
                      for (size_t j = 0; j < len; j++) {
                        uint8_t b;
                        if (!region->GetMemoryAtAddress(cursor + i + j, &b))
                          break;
                        datas.back() += char(b);
                      }
                      i += len;
                    } else
                      break;
                    datas.back() += "\"";
                  } break;
                  case encoding_type::binary: {
                    datas.back() += "blob\n";
                    uint32_t len;
                    if (!region->GetMemoryAtAddress(cursor + i, &len))
                      continue;
                    i += 4;
                    if (len < 65536) {
                      for (size_t j = 0; j < len; j++) {
                        uint8_t b;
                        if (!region->GetMemoryAtAddress(cursor + i + j, &b))
                          break;
                        if (j % 16 == 0)
                          datas.back() += std::format("\n  {:#08x} ", j);
                        else if (j % 4 == 0)
                          datas.back() += " ";
                        datas.back() += std::format("{:02x}", +b);
                      }
                      i += len;
                      datas.back() += "\n";
                    } else
                      break;
                  } break;
                  case encoding_type::boolean: {
                    uint8_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 1;
                    datas.back() += std::format("{}", bool(data));
                  } break;
                  case encoding_type::uint8: {
                    uint8_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 1;
                    datas.back() += std::format("{}", uint8_t(data));
                  } break;
                  case encoding_type::int8: {
                    uint8_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 1;
                    datas.back() += std::format("{}", int8_t(data));
                  } break;

                  case encoding_type::uint16: {
                    uint16_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 2;
                    datas.back() += std::format("{}", uint16_t(data));
                  } break;
                  case encoding_type::int16: {
                    uint16_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 2;
                    datas.back() += std::format("{}", int16_t(data));
                  } break;

                  case encoding_type::uint32: {
                    uint32_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 4;
                    datas.back() += std::format("{}", uint32_t(data));
                  } break;
                  case encoding_type::int32: {
                    uint32_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 4;
                    datas.back() += std::format("{}", int32_t(data));
                  } break;

                  case encoding_type::uint64: {
                    uint64_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 8;
                    datas.back() += std::format("{}", uint64_t(data));
                  } break;
                  case encoding_type::int64: {
                    uint64_t data;
                    if (!region->GetMemoryAtAddress(cursor + i, &data))
                      continue;
                    i += 8;
                    datas.back() += std::format("{}", int64_t(data));
                  } break;
                  case encoding_type::source_location: {
                    uint32_t index;
                    if (!region->GetMemoryAtAddress(cursor + i, &index))
                      continue;
                    i += 4;
                    if (locations.contains(index))
                      datas.back() += locations.at(index);
                    else
                      datas.back() += std::format("{}", index);
                  } break;
                  case encoding_type::node_handle: {
                    uint64_t index;
                    if (!region->GetMemoryAtAddress(cursor + i, &index))
                      continue;
                    i += 8;
                    if (node_handles.contains(index))
                      datas.back() += std::format("node_handle({})",
                                                  node_handles.at(index));
                    else
                      datas.back() += std::format("node_handle({})", index);
                  } break;
                  case encoding_type::cached_string: {
                    uint64_t index;
                    if (!region->GetMemoryAtAddress(cursor + i, &index))
                      continue;
                    i += 8;
                    if (string_cache.contains(index))
                      datas.back() += string_cache.at(index);
                    else
                      datas.back() += std::format("cached_string({})", index);
                  } break;
                  default: {
                    datas.back() +=
                        std::format("TODO: {}", static_cast<int>(type));
                  } break;
                }
              }
            }
            if ((info == "source_location") && (datas.size() == 4) &&
                (names.size() == 4) && (names.at(0) == "index") &&
                (names.at(1) == "function_name") &&
                (names.at(2) == "file_name") && (names.at(3) == "line")) {
              locations.emplace(std::stoull(datas.at(0)),
                                std::format("{} in {}:{}", datas.at(1),
                                            datas.at(2), datas.at(3)));
            }
            if ((info == "spinemarrow.node_handle") && (datas.size() == 2) &&
                (names.size() == 2) && (names.at(0) == "hash") &&
                (names.at(1) == "name")) {
              node_handles.emplace(std::stoull(datas.at(0)), datas.at(1));
            }
            if ((info == "string_cache") && (datas.size() == 2) &&
                (names.size() == 2) && (names.at(0) == "index") &&
                (names.at(1) == "data")) {
              string_cache.emplace(std::stoull(datas.at(0)), datas.at(1));
            }
            std::string params;
            if (false) {
              for (size_t i = 24; i < frame_size;) {
                uint8_t type;
                if (!region->GetMemoryAtAddress(cursor + i, &type))
                  break;
                if (params.size())
                  params += " ";
                params += std::format(" {}:{:#x}", i, type);
                i++;
              }
            }
            for (const auto& [i, d] : datas | std::views::enumerate) {
              if (params.size())
                params += ", ";
              if (size_t(i) < names.size())
                params += names.at(i);
              else
                params += "?";
              params += " = ";
              params += d;
            }

            std::println("[{}] {} {}: {}",
                         std::chrono::tai_clock::time_point{
                             std::chrono::microseconds(time)},
                         level, info, params);
            cursor += frame_size;
          }
        }
      }
    }
    printf("\n");

    int errors = 0;

    DumpRawStream(&dump, MD_LINUX_CMD_LINE, "MD_LINUX_CMD_LINE", &errors);
    DumpRawStream(&dump, MD_LINUX_ENVIRON, "MD_LINUX_ENVIRON", &errors);
    DumpRawStream(&dump, MD_LINUX_LSB_RELEASE, "MD_LINUX_LSB_RELEASE", &errors);
    DumpRawStream(&dump, MD_LINUX_PROC_STATUS, "MD_LINUX_PROC_STATUS", &errors);
    DumpRawStream(&dump, MD_LINUX_CPU_INFO, "MD_LINUX_CPU_INFO", &errors);
    DumpRawStream(&dump, MD_LINUX_MAPS, "MD_LINUX_MAPS", &errors);
  }

  return true;
}

}  // namespace

static void Usage(int argc, const char* argv[], bool error) {
  fprintf(error ? stderr : stdout,
          "Usage: %s [options] <minidump-file> [symbol-path ...]\n"
          "\n"
          "Output a stack trace for the provided minidump\n"
          "\n"
          "Options:\n"
          "\n"
          "  -m         Output in machine-readable format\n"
          "  -s         Output stack contents\n"
          "  -c         Output thread that causes crash or dump only\n"
          "  -b         Brief of the thread that causes crash or dump\n",
          google_breakpad::BaseName(argv[0]).c_str());
}

static void SetupOptions(int argc, const char* argv[], Options* options) {
  int ch;

  options->machine_readable = false;
  options->output_stack_contents = false;
  options->output_requesting_thread_only = false;
  options->brief = false;

  while ((ch = getopt(argc, (char* const*)argv, "bchms")) != -1) {
    switch (ch) {
      case 'h':
        Usage(argc, argv, false);
        exit(0);
        break;

      case 'b':
        options->brief = true;
        break;
      case 'c':
        options->output_requesting_thread_only = true;
        break;
      case 'm':
        options->machine_readable = true;
        break;
      case 's':
        options->output_stack_contents = true;
        break;

      case '?':
        Usage(argc, argv, true);
        exit(1);
        break;
    }
  }

  if ((argc - optind) == 0) {
    fprintf(stderr, "%s: Missing minidump file\n", argv[0]);
    Usage(argc, argv, true);
    exit(1);
  }

  options->minidump_file = argv[optind];

  for (int argi = optind + 1; argi < argc; ++argi)
    options->symbol_paths.push_back(argv[argi]);
}

int main(int argc, const char* argv[]) {
  Options options;
  SetupOptions(argc, argv, &options);

  return PrintMinidumpProcess(options) ? 0 : 1;
}
