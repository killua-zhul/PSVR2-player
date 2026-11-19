#pragma once
#include <string>
#include <vector>
#include "vr_sources.h"

/* List an SMB share directory. `where.key` is the path inside the share
   ("" or "/" for the root). Returns false + err on failure. */
bool smb_list(const VrSrc &where, std::vector<VrSrc> &out, std::string &err);
/* Returns the index of the configured share whose host/share match the URL, or -1. */
int smb_share_index(const std::string &url);
