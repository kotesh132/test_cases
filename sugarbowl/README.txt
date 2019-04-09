----------------------------------------------------------------------
There are about 40 occurrences of comments with 'maybe_wrong_cast' I
added, where the next line has an assignment with a cast to a
particular bit<W> width W on the right hand side.  I quickly added
these to avoid compiler errors now that the p4c compiler has had a
commit for this change to the P4_16 language:

    https://github.com/p4lang/p4c/issues/516

I know that just blindly putting in casts to avoid the compiler errors
isn't the ideal way to handle this, but I don't know the design well
enough yet to know what the correct answer is yet, hence all of the
comments with a particular string, and this note to remind us to
eventually review them and do the right thing, whatever that turns out
to be.

----------------------------------------------------------------------
Andy Fingerhut notes on how this P4_16 version of sug_top.p4 was
created:

Started with the "P4_14+" source code in branch 'forwarding',
directory p4/p4-src/sug, of the ins-asic git repository at this URL:

    ssh://$USER@ins-asic-git.insieme.local:29418/ins-asic

I call it "P4_14+" because it often uses calls to primitive actions
like modify_field() and add_to_field() directly inside control blocks,
which P4_14 does not allow.  This is a useful extension that P4_16
added, but was never added to the P4_14 language.

The p4test program in the open source https://github.com/p4lang/p4c
repository can automatically convert P4_14 source code into P4_16
source code, but only if the program is legal P4_14 source code.

I worked around this by first commenting out the many sections of code
that use these P4_14 extensions, until the remaining code was legal
P4_14.  I converted that with p4test, and then went through the
commented out parts and converted those by hand into P4_16 source
code.

The p4test conversion works _after_ the preprocessing stage, so it
does not preserve #include file structure, or any other preprocessor
operatives like #define or #ifdef.  For #ifdef's, it only converts the
part of the source code that is in the 'taken' branch of an #ifdef or
#ifndef.  It also does not preserve any comments from the original
program.

I then went through at least most of the code and copied over comments
that had not yet been transferred over, and #ifdef's.

At Ashu Agrawal's recommendation, I commented out the #define of
symbols with names beginning with "DISABLE_", because those were added
to see how much savings one could get in a PROF chip if the feature
were not needed.  In a P4->gates flow for a chip that can replace a
Tahoe family ASIC, it needs to be able to do all of those things.

----------------------------------------------------------------------
To do #1:

I have confirmed that the current P4_16 compiler's architecture
v1model.p4 is a temporary P4_16 architecture until the P4 language
design working group comes up with a psa.p4 "Portable Switch
Architecture".

I have also confirmed that with v1model.p4, every bit of metadata in
the type 'struct metadata', and every bit of header in type 'struct
headers', is copied from ingress to egress.

We need a way to limit the data out of ingress to something that we
plan to implement in hardware, which in Tahoe ASICs is something
closer to the following (TBD what the exact list is):

+ 64 bytes of header, perhaps the same as the current code's type
  'struct ig_eg_intrinsic_t'

+ 100 to 200 bits of 'side band' data that goes to the packet
  replication engine, probably type 'struct ig_dp_intrinsic_t'

Until we implement the above, I have for now split ingress and egress
code into separate files sug_ig.p4 and sug_eg.p4.  I have also added
INCLUDE_INGRESS and INCLUDE_EGRESS #define symbols that should
normally both be #define'd.  You can comment those lines out and
everything should still compile, and I have put #ifdef for those
symbols around subsets of the structs in the big 'struct metadata'
structure, so you can see which are accessed only on ingress, which
only on egress, and which on both.

Currently there is very little accessed on egress that I think should
not be.  What is there is probably extracted from the packet in Tahoe
ASICs in an egress parser/field-extractor that is not implemented in
P4 code yet, unless it is in part of the P4_14 original code that I
may not have ported over to P4_16.

I don't know if the current ingress code ever modifies any bits of the
parsed headers, but if it does, that should preferably be at last a
warning and maybe an error flagged by the compiler.  It might be
useful to allow it to be modified for 'scratch temporary space' in the
ingress pipeline, but if none of those changes are propagated through
to egress, any such changes will be lost at the end of the ingress
pipeline.

Idea: We could make some #ifdef-wrapped code that copies the values of
*all* headers at the beginning of the ingress control block, and use
those to compare against the final values of all headers at the end of
the ingress control block, and set some special 'drop on egress' flag
that would cause the packet to be dropped if there were any
differences.  That would at least catch some cases of changing header
values on ingress.

----------------------------------------------------------------------
To do #2:

The original sug_top.p4 source code was written with a field
programmable P4 target device called the PROF chip in mind, similar to
Barefoot's Tofino.  For such a device, it would only be necessary to
program into it either the ACI feature set, or the standalone feature
set, one at a time (or perhaps there are a few other variations
besides those two).  Thus there were many places with '#ifdef
ACI_TOR_MODE' followed by some conditionally included P4 code.
Sometimes there was an #else with different P4 code after it.

For the P4->gates flow we are considering using, we still need a
single ASIC that can perform in any of those modes, selected via one
or more config registers at run time, not at compile time.

I have left the #ifdef and #ifndef of ACI_TOR_MODE in the code in
comments for now, to show where they were when they were not commented
out.  In all except one case explained below, the program now has
behavior conditionally selected at packet forwarding time based upon
the value of a 1-bit 'config register' put into a metadata field on
ingress by the table CFG_ig_aci_tor_mode, and on egress by the table
CFG_eg_aci_tor_mode.  The default setting of this config register is
0, for standalone mode.  You can change the action for that table from
the control plane (e.g. via simple_switch_CLI) if you wish to get the
ACI behavior.

TBD: sug_sizes.p4 has these #define symbols whose values depend on
whether ACI_TOR_MODE is #define'd or not:

    #ifdef ACI_TOR_MODE
    #define NUM_CHIPS_PER_CHASIS                   1
    #define NUM_PORTS_PER_CHASIS                  NUM_PORTS_PER_CHIP
    #else
    #define NUM_CHIPS_PER_CHASIS                   128
    #define NUM_PORTS_PER_CHASIS                  4096
    #endif

In addition, there are _other_ #define symbols whose values are
calculated from these, and then used as table sizes.  Need to think
about how to handle this at run time.

----------------------------------------------------------------------
2018-Feb-22 changes

I made some small changes to sug_top.p4 so that it would compile with
the latest version of the open source P4_16 compiler, the source of
which can be obtained with these commands:

% git clone https://github.com/p4lang/p4c
% cd p4c
% git checkout 80f8970b5ec8e57c4a3611da343461b5b0a8dda3
% git log . | head -n 3
commit 80f8970b5ec8e57c4a3611da343461b5b0a8dda3
Author: Chris Dodd <cdodd@acm.org>
Date:   Fri Feb 16 12:28:50 2018 -0800

The only changes made were removing the uses of the Checksum16 extern,
replacing them with calls to the newer built-in functions
verify_checksum() and update_checksum().

Commands run to create the output files in the directory
p4c-output-files-2018-02-16, running on an Ubuntu 16.04 Linux VM where
the p4lang/behavioral-model and p4lang/p4c repositories had both been
installed using the instructions in their README (probably only
p4lang/p4c install is enough for this, but I have not verified that).

% mkdir p4c-output-files-2018-02-16
% cd p4c-output-files-2018-02-16
% time p4c-bm2-ss ../sug_top.p4 -o sug_top.json >& p4c-out.log

Took 6 mins 58 sec wall clock time, 5 min 53 sec CPU time.  This is
about twice as long as 1 year older version of p4c took -- I have not
attempted to investigate where the CPU time is being spent.

Output files created from last command:
    p4c-out.log
    sug_top.json

% P4C_INSTALL=/home/jafinger/p4c
% time p4c-graphs -I${P4C_INSTALL}/p4include ../sug_top.p4

Output files created from last command:
    computeChecksum.dot
    DeparserImpl.dot
    egress.dot
    ingress.dot
    ParserImpl.dot
    verifyChecksum.dot

I then copied ParserImpl.dot to ParserImpl-unique-accept-states.dot,
and edited it by hand to replace all occurrences of the 'accept' node
with uniquely named nodes 'accept01' through 'accept42', and 'reject'
with 'reject01' through 'reject03'.  This makes the auto-generated
graphs have fewer long edges in them, going from many places to a
common accept state.

Used 'dot' command from 'graphviz' package to create PDF version:

# On Ubuntu 16.04 Linux VM:
% sudo apt-get install graphviz

Generate PDF files for every .dot file:

% for j in *.dot
> do
> k=`basename $j`.pdf
> dot -Tpdf $j > $k
> done

----------------------------------------------------------------------
