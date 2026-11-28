/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file testcodedata.cc
/// \brief Unit tests for CodeDataAnalysis::runModel section handling
///
/// These drive the two guards added for FL-25:
///   1. a loader that does not override getNextSection leaves the
///      LoadImageSection record unfilled (address.base == NULL), and
///   2. an image whose sections are all zero-sized leaves lastaddr invalid.
/// Both used to dereference a null AddrSpace in Address::operator+.

#include "architecture.hh"
#include "codedata.hh"
#include "loadimage.hh"
#include "test.hh"
#include <iostream>

namespace ghidra {

class CodeDataTestEnvironment {
  Architecture *g;
public:
  CodeDataTestEnvironment(void);
  ~CodeDataTestEnvironment(void);
  static void build(void);
};

static Architecture *glb;
static CodeDataTestEnvironment theEnviron;

CodeDataTestEnvironment::CodeDataTestEnvironment(void)

{
  g = (Architecture *)0;
}

void CodeDataTestEnvironment::build(void)

{
  if (theEnviron.g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  theEnviron.g = xmlCapability->buildArchitecture("", "", &cout);
  theEnviron.g->init(store);

  glb = theEnviron.g;
}

CodeDataTestEnvironment::~CodeDataTestEnvironment(void)

{
  if (g != (Architecture *)0)
    delete g;
}

/// \brief A loader that does not override getNextSection
///
/// The base LoadImage::getNextSection returns false without touching the
/// record, so the first iteration of runModel sees an unfilled section.
class UnfilledSectionLoader : public LoadImage {
public:
  UnfilledSectionLoader(void) : LoadImage("unfilled") {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) {
    throw DataUnavailError("no data");
  }
  virtual string getArchType(void) const { return "test"; }
  virtual void adjustVma(long adjust) {}
};

/// \brief A loader returning valid-address sections that are all zero-sized
class ZeroSizeSectionLoader : public LoadImage {
  AddrSpace *space;
  mutable int4 count;
public:
  ZeroSizeSectionLoader(AddrSpace *sp) : LoadImage("zerosize"), space(sp), count(0) {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) {
    throw DataUnavailError("no data");
  }
  virtual string getArchType(void) const { return "test"; }
  virtual void adjustVma(long adjust) {}
  virtual bool getNextSection(LoadImageSection &sec) const {
    if (count >= 2) return false;
    sec.address = Address(space, (uintb)(0x1000 + count * 0x100));
    sec.size = 0;
    sec.flags = 0;
    count += 1;
    return true;
  }
};

/// Run runModel against a replacement loader and restore the original.
static void runModelWithLoader(LoadImage *replacement)

{
  LoadImage *saved = glb->loader;
  glb->loader = replacement;
  CodeDataAnalysis codedata;
  codedata.init(glb);
  codedata.runModel();
  // Nothing to model: no valid sections means no hits and no code units.
  ASSERT(codedata.modelhits.empty());
  ASSERT(codedata.codeunit.empty());
  ASSERT(codedata.targethits.empty());
  glb->loader = saved;
}

TEST(codedata_runmodel_unfilled_section) {
  CodeDataTestEnvironment::build();
  UnfilledSectionLoader loader;
  runModelWithLoader(&loader);
}

TEST(codedata_runmodel_zero_size_sections) {
  CodeDataTestEnvironment::build();
  ZeroSizeSectionLoader loader(glb->translate->getDefaultCodeSpace());
  runModelWithLoader(&loader);
}

} // End namespace ghidra
