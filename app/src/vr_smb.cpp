#include "vr_smb.h"

#include "cJSON.h"
#include "eng_boot_trace.h"
#include "vr_sources.h"

#define HAVE_STDINT_H 1
#define HAVE_TIME_H 1
extern "C" {
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
}

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define PS5VR_DIR "/data/ps5vr"
#define PS5VR_SMB PS5VR_DIR "/smb.json"

namespace {
struct SmbShare {
    std::string name, url, host, share, user, pass, domain;
};

bool parse_url(const std::string &url, SmbShare &s) {
    s.url = url;
    std::string u = url;
    size_t pos = u.find("://");
    if (pos == std::string::npos || u.substr(0, pos) != "smb") return false;
    pos += 3;
    size_t at = u.find('@', pos);
    std::string hostpart = u.substr(pos);
    if (at != std::string::npos) {
        std::string cred = u.substr(pos, at - pos);
        hostpart = u.substr(at + 1);
        size_t colon = cred.find(':');
        if (colon != std::string::npos) { s.user = cred.substr(0, colon); s.pass = cred.substr(colon + 1); }
        else s.user = cred;
    }
    // host/share/path
    size_t slash = hostpart.find('/');
    if (slash == std::string::npos) return false;
    s.host = hostpart.substr(0, slash);
    std::string rest = hostpart.substr(slash + 1);
    size_t slash2 = rest.find('/');
    if (slash2 == std::string::npos) { s.share = rest; }
    else { s.share = rest.substr(0, slash2); }
    return !s.host.empty() && !s.share.empty();
}

std::vector<SmbShare> load_shares() {
    std::vector<SmbShare> out;
    FILE *f = std::fopen(PS5VR_SMB, "r");
    if (!f) return out;
    char buf[4096];
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = 0;
    cJSON *root = cJSON_Parse(buf);
    if (!root) return out;
    cJSON *arr = cJSON_GetObjectItem(root, "shares");
    if (!arr || !cJSON_IsArray(arr)) { cJSON_Delete(root); return out; }
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        SmbShare s;
        cJSON *v;
        if ((v = cJSON_GetObjectItem(it, "name"))) s.name = v->valuestring ? v->valuestring : "";
        if ((v = cJSON_GetObjectItem(it, "host"))) s.host = v->valuestring ? v->valuestring : "";
        if ((v = cJSON_GetObjectItem(it, "share"))) s.share = v->valuestring ? v->valuestring : "";
        if ((v = cJSON_GetObjectItem(it, "user"))) s.user = v->valuestring ? v->valuestring : "";
        if ((v = cJSON_GetObjectItem(it, "password"))) s.pass = v->valuestring ? v->valuestring : "";
        if ((v = cJSON_GetObjectItem(it, "domain"))) s.domain = v->valuestring ? v->valuestring : "";
        // backward compat: url field
        if (s.host.empty()) {
            if ((v = cJSON_GetObjectItem(it, "url"))) {
                std::string url = v->valuestring ? v->valuestring : "";
                // parse smb://user:pass@host/share
                size_t pos = url.find("://");
                if (pos != std::string::npos && url.substr(0, pos) == "smb") {
                    pos += 3;
                    size_t at = url.find('@', pos);
                    std::string hostpart = url.substr(pos);
                    if (at != std::string::npos) {
                        std::string cred = url.substr(pos, at - pos);
                        hostpart = url.substr(at + 1);
                        size_t colon = cred.find(':');
                        if (colon != std::string::npos) { s.user = cred.substr(0, colon); s.pass = cred.substr(colon + 1); }
                        else s.user = cred;
                    }
                    size_t slash = hostpart.find('/');
                    if (slash != std::string::npos) {
                        s.host = hostpart.substr(0, slash);
                        std::string rest = hostpart.substr(slash + 1);
                        size_t slash2 = rest.find('/');
                        s.share = (slash2 == std::string::npos) ? rest : rest.substr(0, slash2);
                    }
                }
            }
        }
        if (s.name.empty()) s.name = s.host + "/" + s.share;
        if (!s.host.empty() && !s.share.empty()) out.push_back(s);
    }
    cJSON_Delete(root);
    return out;
}

std::string make_url(const SmbShare &c, const std::string &rel) {
    std::string url = "smb://";
    if (!c.user.empty()) {
        url += c.user;
        if (!c.pass.empty()) url += ":" + c.pass;
        url += "@";
    }
    url += c.host + "/" + c.share;
    if (!rel.empty() && rel != "/") {
        if (rel[0] != '/') url += "/";
        url += rel;
    }
    return url;
}
} // namespace

bool smb_list(const VrSrc &where, std::vector<VrSrc> &out, std::string &err)
{
    out.clear();
    if (where.kind == SRC_SMB_LIST) {
        auto shares = load_shares();
        if (shares.empty()) {
            err = "No SMB shares configured. Open http://" + vr_console_ip() + ":" +
                  std::to_string(vr_settings_server_port()) + " on your phone/PC to add one.";
            return false;
        }
        for (size_t i = 0; i < shares.size(); i++) {
            VrSrc it;
            it.kind = SRC_SMB;
            it.name = shares[i].name;
            it.key = "/";
            it.base = std::to_string(i);
            it.detail = shares[i].host + "/" + shares[i].share;
            out.push_back(it);
        }
        return true;
    }

    int idx = -1;
    try { idx = std::stoi(where.base); } catch (...) { idx = -1; }
    auto shares = load_shares();
    if (idx < 0 || idx >= (int)shares.size()) {
        err = "SMB share not found";
        return false;
    }
    const SmbShare &cfg = shares[idx];

    std::string path = where.key.empty() ? "" : where.key;
    if (path == "/") path = "";
    if (!path.empty() && path[0] == '/') path = path.substr(1);

    smb2_context *smb = smb2_init_context();
    if (!smb) { err = "SMB: could not init context"; return false; }
    smb2_set_timeout(smb, 5);
    if (!cfg.user.empty()) smb2_set_user(smb, cfg.user.c_str());
    if (!cfg.pass.empty()) smb2_set_password(smb, cfg.pass.c_str());
    if (!cfg.domain.empty()) smb2_set_domain(smb, cfg.domain.c_str());

    int rc = smb2_connect_share(smb, cfg.host.c_str(), cfg.share.c_str(),
                                cfg.user.empty() ? nullptr : cfg.user.c_str());
    if (rc != 0) {
        err = std::string("SMB connect failed: ") + smb2_get_error(smb);
        smb2_destroy_context(smb);
        return false;
    }

    smb2dir *dir = smb2_opendir(smb, path.empty() ? "" : path.c_str());
    if (!dir) {
        err = std::string("SMB open dir failed: ") + smb2_get_error(smb);
        smb2_disconnect_share(smb);
        smb2_destroy_context(smb);
        return false;
    }

    std::vector<VrSrc> dirs, files;
    smb2dirent *e;
    while ((e = smb2_readdir(smb, dir))) {
        if (!e->name || !std::strcmp(e->name, ".") || !std::strcmp(e->name, ".."))
            continue;
        VrSrc it;
        it.name = e->name;
        std::string rel = path;
        if (!rel.empty()) rel += "/";
        rel += e->name;
        if (e->st.smb2_type == SMB2_TYPE_DIRECTORY) {
            it.kind = SRC_SMB;
            it.key = (rel.empty() ? std::string("/") : rel);
            it.base = std::to_string(idx);
            it.detail = "Folder";
            dirs.push_back(it);
        } else {
            const std::string n = e->name;
            std::string lower = n;
            for (char &c : lower) c = (char)std::tolower((unsigned char)c);
            bool vid = false;
            const char *exts[] = {".mp4",".mkv",".mov",".m4v",".webm",".ts",".m2ts",".mts",".avi",".mpg",".mpeg"};
            for (const char *ex : exts)
                if (lower.size() >= std::strlen(ex) && lower.compare(lower.size()-std::strlen(ex), std::strlen(ex), ex) == 0) { vid = true; break; }
            if (!vid) continue;
            it.kind = SRC_PLAY;
            it.url = make_url(cfg, rel.empty() ? std::string("/") + n : rel);
            it.detail = "";
            files.push_back(it);
        }
    }
    smb2_closedir(smb, dir);
    smb2_disconnect_share(smb);
    smb2_destroy_context(smb);

    auto by_name = [](const VrSrc &a, const VrSrc &b) { return strcasecmp(a.name.c_str(), b.name.c_str()) < 0; };
    std::sort(dirs.begin(), dirs.end(), by_name);
    std::sort(files.begin(), files.end(), by_name);
    out = dirs;
    out.insert(out.end(), files.begin(), files.end());
    if (out.empty())
        err = "This folder is empty";
    return true;
}

int smb_share_index(const std::string &url) {
    // parse host/share from url
    std::string u = url;
    size_t pos = u.find("://");
    if (pos == std::string::npos) return -1;
    pos += 3;
    size_t at = u.find('@', pos);
    std::string hostpart = (at == std::string::npos) ? u.substr(pos) : u.substr(at + 1);
    size_t slash = hostpart.find('/');
    if (slash == std::string::npos) return -1;
    std::string host = hostpart.substr(0, slash);
    std::string rest = hostpart.substr(slash + 1);
    size_t slash2 = rest.find('/');
    std::string share = (slash2 == std::string::npos) ? rest : rest.substr(0, slash2);

    FILE *f = std::fopen("/data/ps5vr/smb.json", "r");
    if (!f) return -1;
    char buf[4096];
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = 0;
    cJSON *root = cJSON_Parse(buf);
    if (!root) return -1;
    cJSON *arr = cJSON_GetObjectItem(root, "shares");
    if (!arr || !cJSON_IsArray(arr)) { cJSON_Delete(root); return -1; }
    int idx = 0;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        const char *ho = cJSON_GetStringValue(cJSON_GetObjectItem(it, "host"));
        const char *sh = cJSON_GetStringValue(cJSON_GetObjectItem(it, "share"));
        std::string h = ho ? ho : "";
        std::string shs = sh ? sh : "";
        // backward compat: url
        if (h.empty()) {
            const char *ur = cJSON_GetStringValue(cJSON_GetObjectItem(it, "url"));
            if (ur) {
                std::string u2 = ur;
                size_t p2 = u2.find("://");
                if (p2 != std::string::npos) {
                    p2 += 3;
                    size_t a2 = u2.find('@', p2);
                    std::string hp = (a2 == std::string::npos) ? u2.substr(p2) : u2.substr(a2 + 1);
                    size_t sl = hp.find('/');
                    if (sl != std::string::npos) {
                        h = hp.substr(0, sl);
                        std::string r = hp.substr(sl + 1);
                        size_t sl2 = r.find('/');
                        shs = (sl2 == std::string::npos) ? r : r.substr(0, sl2);
                    }
                }
            }
        }
        if (h == host && shs == share) {
            cJSON_Delete(root);
            return idx;
        }
        idx++;
    }
    cJSON_Delete(root);
    return -1;
}
