#include <cstddef>
#include <string_view>

#include <gtest/gtest.h>
#include "upb/upb/jspb/decode.h"
#include "upb/upb/jspb/encode.h"
#include "upb/upb/mem/arena.h"
#include "upb/upb/mem/arena.hpp"
#include "upb/upb/message/message.h"
#include "upb/upb/mini_table/extension_registry.h"
#include "upb/upb/mini_table/message.h"
#include "upb/upb/test/fuzz_util.h"

// begin:google_only
// #include "testing/fuzzing/fuzztest.h"
// end:google_only

namespace {

static void DecodeEncodeArbitrarySchemaAndPayload(
    const upb::fuzz::MiniTableFuzzInput& input,
    std::string_view proto_payload) {
// Lexan does not have setenv
#ifndef _MSC_VER
  setenv("FUZZTEST_STACK_LIMIT", "262144", 1);
#endif
  upb::Arena arena;
  upb_ExtensionRegistry* exts;
  const upb_MiniTable* mini_table =
      upb::fuzz::BuildMiniTable(input, &exts, arena.ptr());
  if (!mini_table) return;
  upb_Message* msg = upb_Message_New(mini_table, arena.ptr());
  upb_JspbDecode(proto_payload.data(), proto_payload.size(), msg, mini_table,
                 exts, 0, arena.ptr(), nullptr);

  size_t size =
      upb_JspbEncode(msg, mini_table, nullptr, 0, nullptr, 0, nullptr);
  char* jspb_buf = (char*)upb_Arena_Malloc(arena.ptr(), size + 1);

  size_t written =
      upb_JspbEncode(msg, mini_table, nullptr, 0, jspb_buf, size + 1, nullptr);
  EXPECT_EQ(written, size);
}
FUZZ_TEST(FuzzTest, DecodeEncodeArbitrarySchemaAndPayload);

TEST(FuzzTest, Simple) {
  DecodeEncodeArbitrarySchemaAndPayload({}, "[null, {}]");
}

TEST(FuzzTest, DecodeExtensionEnsurePresenceInitialized) {
  DecodeEncodeArbitrarySchemaAndPayload(
      {.mini_descriptors = {"\031", "S", "\364", "", "", "j", "\303", "",
                            "\224", "\277"},
       .enum_mini_descriptors = {},
       .extensions = "_C-\236$*)C0C>",
       .links = {4041515984, 2147483647, 1929379871, 0, 3715937258,
                 4294967295}},
      "[1, null, {}]");
}

}  // namespace
