/* This file only contains some structure instanciation and tests to see if
 * everything is working as intended.
 * None of the following code needs to be implemented in HaCl*
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "utils/common.h"
#include "utils/module_tests.h"
#include "common/sae.h"
#include "wpabuf.h"
#include "crypto/crypto.h"

#define SSID "My SSID"
#define GRP_ID 19
#define NB_TESTS 1000
static const uint8_t macA[] = { 0x98, 0xe7, 0x43, 0xd8, 0x6f, 0xbd };
static const uint8_t macB[] = { 0x04, 0xed, 0x33, 0xc0, 0x85, 0x9b };

static struct wpabuf* auth_build_sae_commit(struct sae_data* sae, char* pwd, char* pwd_id, struct sae_pt* pt) {
	struct wpabuf* buf;
	int use_pt = 0;
	size_t pwd_len = strlen(pwd);

	use_pt = pt != NULL;

	if (use_pt &&
		sae_prepare_commit_pt(sae, pt, macA, macB,
			NULL, NULL) < 0) {
		sae_deinit_pt(pt);
		return NULL;
	}
	if (!use_pt &&
		sae_prepare_commit(macA, macB, (const u8*) pwd, pwd_len,
			sae) < 0) {
		fprintf(stderr, "SAE: Could not pick PWE\n");
		return NULL;
	}

	buf = wpabuf_alloc(SAE_COMMIT_MAX_LEN +
		(pwd_id ? 3 + strlen(pwd_id) : 0));
	if (buf &&
		sae_write_commit(sae, buf, sae->tmp ?
			sae->tmp->anti_clogging_token : NULL,
			pwd_id) < 0) {
		wpabuf_free(buf);
		buf = NULL;
	}

	return buf;
}


static struct wpabuf* auth_build_sae_confirm(struct sae_data* sae) {
	struct wpabuf* buf;

	buf = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
	if (buf == NULL)
		return NULL;

	if (sae_write_confirm(sae, buf) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	return buf;
}

static int sae_test_custom(int group_id, char* pwd, char* pwd_id, struct sae_pt* pt) {
	int err = -1;
	struct sae_data saeA, saeB;

	struct wpabuf* commitA = NULL, * commitB = NULL;
	struct wpabuf* confirmA = NULL, * confirmB = NULL;

	int h2e = pwd_id != NULL;

	memset(&saeA, 0, sizeof(saeA));
	memset(&saeB, 0, sizeof(saeB));

	// Set the group
	err = sae_set_group(&saeA, group_id);
	if (err) goto end;
	err = sae_set_group(&saeB, group_id);
	if (err) goto end;

	// Both part compute the commit message
	commitA = auth_build_sae_commit(&saeA, pwd, pwd_id, pt);
	if (commitA == NULL) goto end;
	commitB = auth_build_sae_commit(&saeB, pwd, pwd_id, pt);
	if (commitB == NULL) goto end;

	// Both part receive the commit, parse it, and process it
	err = sae_parse_commit(&saeA, wpabuf_mhead_u8(commitB), wpabuf_len(commitB),
		NULL, NULL, NULL, h2e);
	if (err < 0)  goto end;
	err = sae_process_commit(&saeA);
	if (err != 0) goto end;
	err = sae_parse_commit(&saeB, wpabuf_mhead_u8(commitA), wpabuf_len(commitA),
		NULL, NULL, NULL, h2e);
	if (err < 0) goto end;
	err = sae_process_commit(&saeB);
	if (err != 0) goto end;

	// Build the confirmation message
	confirmA = auth_build_sae_confirm(&saeA);
	if (confirmA == NULL) goto end;
	confirmB = auth_build_sae_confirm(&saeB);
	if (confirmB == NULL) goto end;

	// Both part verify the confirmation message of the other
	err = sae_check_confirm(&saeA, wpabuf_mhead_u8(confirmB), wpabuf_len(confirmB));
	if (err != 0) goto end;
	err = sae_check_confirm(&saeB, wpabuf_mhead_u8(confirmA), wpabuf_len(confirmA));
	if (err != 0) goto end;

end:
	sae_clear_data(&saeA);
	sae_clear_data(&saeB);
	if (commitA) wpabuf_free(commitA);
	if (commitB) wpabuf_free(commitB);
	if (confirmA) wpabuf_free(confirmA);
	if (confirmB) wpabuf_free(confirmB);

	return err;
}

int main(int argc, char** argv) {
	int err = 0;
	int idx = 1;

#ifdef DRAGONSTAR_DEBUG
	wpa_debug_level = MSG_EXCESSIVE;
	wpa_debug_show_keys = 1;
	wpa_printf(MSG_DEBUG, "DRAGONSTAR DEBUG MODE ACTIVATED");
#endif

#ifndef PERF
	if (common_module_tests())
		fprintf(stderr, "hostapd_test: NOK\n");
	else
		fprintf(stderr, "hostapd_test: OK\n");
#endif
	int group_id = 19;
	char* pwd_id = NULL;
	struct sae_pt* pt = NULL;
	if (strcmp(argv[idx], "-i") == 0) {
		idx++;
		pwd_id = argv[idx++];
	}

	// Go through all passwords
	for (int i = idx; i < argc; i++) {
		//Run two sessions (A and B) from commit to confirmation 
#ifndef PERF
		fprintf(stderr, "custom_pwd_test_%s\n", argv[i]);
#endif
		if (pwd_id) {
			pt = sae_derive_pt(NULL, (const uint8_t*) SSID, strlen(SSID),
				(const uint8_t*) argv[i], strlen(argv[i]), pwd_id);
			if (pt == NULL)
				fprintf(stderr, "error when computing pt\n");
		}
#ifdef PERF
		for (int j = 0; j < NB_TESTS; j++) {
#endif
			err |= sae_test_custom(group_id, argv[i], pwd_id, pt);
#ifdef PERF
		}
#endif
		if (pt) { sae_deinit_pt(pt); pt = NULL; }
	}

	return err;
}
