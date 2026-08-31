// ============================================================
//  Park Test · local settings
//
//  Both values come from your Supabase project:
//    Project Settings > API
//
//  1. Project URL, with /rest/v1 added on the end
//  2. The anon / public key (the long one, NOT service_role)
//
//  Safe to commit. The anon key only reaches functions that
//  demand your passphrase, and the tables themselves are
//  locked away from it entirely.
//
//  NEVER put the service_role key here. That one bypasses
//  everything.
//
//  This is the ONLY file you need to edit. Future versions of
//  index.html can be dropped in without touching it.
// ============================================================

window.PARK_TEST_API = "https://qikaqlooqrdgbjrgjeqs.supabase.co/rest/v1";

window.PARK_TEST_KEY = "sb_publishable_6uhPEcefMqVcFdr2gZ31nQ_xubI4N-X";
