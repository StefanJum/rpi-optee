// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <compiler.h>
#include <initcall.h>
#include <io.h>
#include <kernel/linker.h>
#include <kernel/msg_param.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/tee_cryp_utl.h>
#include <tee/uuid.h>
#include <util.h>
#include <string.h>

#ifdef CFG_CORE_FFA
#include <kernel/thread_spmc.h>
#endif

#define SHM_CACHE_ATTRS	\
	(uint32_t)(core_mmu_is_shm_cached() ? \
		   TEE_MATTR_MEM_TYPE_CACHED : TEE_MATTR_MEM_TYPE_DEV)

/* Sessions opened from normal world */
static struct tee_ta_session_head tee_open_sessions =
TAILQ_HEAD_INITIALIZER(tee_open_sessions);

#ifdef CFG_CORE_RESERVED_SHM
static struct mobj *shm_mobj;
#endif
#ifdef CFG_SECURE_DATA_PATH
static struct mobj **sdp_mem_mobjs;
#endif

static unsigned int session_pnum;

static bool __maybe_unused param_mem_from_mobj(struct param_mem *mem,
					       struct mobj *mobj,
					       const paddr_t pa,
					       const size_t sz)
{
	paddr_t b;

	if (mobj_get_pa(mobj, 0, 0, &b) != TEE_SUCCESS)
		panic("mobj_get_pa failed");

	if (!core_is_buffer_inside(pa, MAX(sz, 1UL), b, mobj->size))
		return false;

	mem->mobj = mobj_get(mobj);
	mem->offs = pa - b;
	mem->size = sz;
	return true;
}

#ifdef CFG_CORE_FFA
static TEE_Result set_fmem_param(const struct optee_msg_param_fmem *fmem,
				 struct param_mem *mem)
{
	size_t req_size = 0;
	uint64_t global_id = READ_ONCE(fmem->global_id);
	size_t sz = READ_ONCE(fmem->size);

	if (global_id == OPTEE_MSG_FMEM_INVALID_GLOBAL_ID && !sz) {
		mem->mobj = NULL;
		mem->offs = 0;
		mem->size = 0;
		return TEE_SUCCESS;
	}
	mem->mobj = mobj_ffa_get_by_cookie(global_id,
					   READ_ONCE(fmem->internal_offs));
	if (!mem->mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->offs = reg_pair_to_64(READ_ONCE(fmem->offs_high),
				   READ_ONCE(fmem->offs_low));
	mem->size = sz;

	/*
	 * Check that the supplied offset and size is covered by the
	 * previously verified MOBJ.
	 */
	if (ADD_OVERFLOW(mem->offs, mem->size, &req_size) ||
	    mem->mobj->size < req_size)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
#else /*!CFG_CORE_FFA*/
/* fill 'struct param_mem' structure if buffer matches a valid memory object */
static TEE_Result set_tmem_param(const struct optee_msg_param_tmem *tmem,
				 uint32_t attr, struct param_mem *mem)
{
	struct mobj __maybe_unused **mobj = NULL;
	paddr_t pa = READ_ONCE(tmem->buf_ptr);
	size_t sz = READ_ONCE(tmem->size);
	struct mobj *rmobj = NULL;

	/*
	 * Handle NULL memory reference
	 */
	if (!pa) {
		mem->mobj = NULL;
		mem->offs = 0;
		mem->size = 0;
		return TEE_SUCCESS;
	}

	/* Handle non-contiguous reference from a shared memory area */
	if (attr & OPTEE_MSG_ATTR_NONCONTIG) {
		uint64_t shm_ref = READ_ONCE(tmem->shm_ref);

		mem->mobj = msg_param_mobj_from_noncontig(pa, sz, shm_ref,
							  false);
		if (!mem->mobj)
			return TEE_ERROR_BAD_PARAMETERS;
		mem->offs = 0;
		mem->size = sz;
		return TEE_SUCCESS;
	}

#ifdef CFG_CORE_RESERVED_SHM
	/* Handle memory reference in the contiguous shared memory */
	if (param_mem_from_mobj(mem, shm_mobj, pa, sz))
		return TEE_SUCCESS;
#endif

#ifdef CFG_SECURE_DATA_PATH
	/* Handle memory reference to Secure Data Path memory areas */
	for (mobj = sdp_mem_mobjs; *mobj; mobj++)
		if (param_mem_from_mobj(mem, *mobj, pa, sz))
			return TEE_SUCCESS;
#endif
	rmobj = mobj_protmem_get_by_pa(pa, sz);
	if (rmobj) {
		bool rc = param_mem_from_mobj(mem, rmobj, pa, sz);

		mobj_put(rmobj);
		if (rc)
			return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

#ifdef CFG_CORE_DYN_SHM
static TEE_Result set_rmem_param(const struct optee_msg_param_rmem *rmem,
				 struct param_mem *mem)
{
	size_t req_size = 0;
	uint64_t shm_ref = READ_ONCE(rmem->shm_ref);
	size_t sz = READ_ONCE(rmem->size);

	mem->mobj = mobj_reg_shm_get_by_cookie(shm_ref);
	if (!mem->mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->offs = READ_ONCE(rmem->offs);
	mem->size = sz;

	/*
	 * Check that the supplied offset and size is covered by the
	 * previously verified MOBJ.
	 */
	if (ADD_OVERFLOW(mem->offs, mem->size, &req_size) ||
	    mem->mobj->size < req_size)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
#endif /*CFG_CORE_DYN_SHM*/
#endif /*!CFG_CORE_FFA*/

static TEE_Result copy_in_params(const struct optee_msg_param *params,
				 uint32_t num_params,
				 struct tee_ta_param *ta_param,
				 uint64_t *saved_attr)
{
	TEE_Result res;
	size_t n;
	uint8_t pt[TEE_NUM_PARAMS] = { 0 };

	if (num_params > TEE_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(ta_param, 0, sizeof(*ta_param));

	for (n = 0; n < num_params; n++) {
		uint32_t attr;

		saved_attr[n] = READ_ONCE(params[n].attr);

		if (saved_attr[n] & OPTEE_MSG_ATTR_META)
			return TEE_ERROR_BAD_PARAMETERS;

		attr = saved_attr[n] & OPTEE_MSG_ATTR_TYPE_MASK;
		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			pt[n] = TEE_PARAM_TYPE_NONE;
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			pt[n] = TEE_PARAM_TYPE_VALUE_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			ta_param->u[n].val.a = READ_ONCE(params[n].u.value.a);
			ta_param->u[n].val.b = READ_ONCE(params[n].u.value.b);
			break;
#ifdef CFG_CORE_FFA
		case OPTEE_MSG_ATTR_TYPE_FMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_INOUT:
			res = set_fmem_param(&params[n].u.fmem,
					     &ta_param->u[n].mem);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;
			break;
#else /*!CFG_CORE_FFA*/
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			res = set_tmem_param(&params[n].u.tmem, saved_attr[n],
					     &ta_param->u[n].mem);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			break;
#ifdef CFG_CORE_DYN_SHM
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			res = set_rmem_param(&params[n].u.rmem,
					     &ta_param->u[n].mem);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
			break;
#endif /*CFG_CORE_DYN_SHM*/
#endif /*!CFG_CORE_FFA*/
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	ta_param->types = TEE_PARAM_TYPES(pt[0], pt[1], pt[2], pt[3]);

	return TEE_SUCCESS;
}

static void cleanup_shm_refs(const uint64_t *saved_attr,
			     struct tee_ta_param *param, uint32_t num_params)
{
	size_t n;

	for (n = 0; n < MIN((unsigned int)TEE_NUM_PARAMS, num_params); n++) {
		switch (saved_attr[n]) {
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
#ifdef CFG_CORE_DYN_SHM
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
#endif
			mobj_put(param->u[n].mem.mobj);
			break;
		default:
			break;
		}
	}
}

static void copy_out_param(struct tee_ta_param *ta_param, uint32_t num_params,
			   struct optee_msg_param *params, uint64_t *saved_attr)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (TEE_PARAM_TYPE_GET(ta_param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			switch (saved_attr[n] & OPTEE_MSG_ATTR_TYPE_MASK) {
			case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
			case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
				params[n].u.tmem.size = ta_param->u[n].mem.size;
				break;
			case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
			case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
				params[n].u.rmem.size = ta_param->u[n].mem.size;
				break;
			default:
				break;
			}
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = ta_param->u[n].val.a;
			params[n].u.value.b = ta_param->u[n].val.b;
			break;
		default:
			break;
		}
	}
}

/*
 * Extracts mandatory parameter for open session.
 *
 * Returns
 * false : mandatory parameter wasn't found or malformatted
 * true  : paramater found and OK
 */
static TEE_Result get_open_session_meta(size_t num_params,
					struct optee_msg_param *params,
					size_t *num_meta, TEE_UUID *uuid,
					TEE_Identity *clnt_id)
{
	const uint32_t req_attr = OPTEE_MSG_ATTR_META |
				  OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;

	if (num_params < 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].attr != req_attr || params[1].attr != req_attr)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_uuid_from_octets(uuid, (void *)&params[0].u.value);
	clnt_id->login = params[1].u.value.c;
	switch (clnt_id->login) {
	case TEE_LOGIN_PUBLIC:
	case TEE_LOGIN_REE_KERNEL:
		memset(&clnt_id->uuid, 0, sizeof(clnt_id->uuid));
		break;
	case TEE_LOGIN_USER:
	case TEE_LOGIN_GROUP:
	case TEE_LOGIN_APPLICATION:
	case TEE_LOGIN_APPLICATION_USER:
	case TEE_LOGIN_APPLICATION_GROUP:
		tee_uuid_from_octets(&clnt_id->uuid,
				     (void *)&params[1].u.value);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*num_meta = 2;
	return TEE_SUCCESS;
}

static void entry_open_session(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s = NULL;
	TEE_Identity clnt_id = { };
	TEE_UUID uuid = { };
	struct tee_ta_param param = { };
	size_t num_meta = 0;
	uint64_t saved_attr[TEE_NUM_PARAMS] = { 0 };

	res = get_open_session_meta(num_params, arg->params, &num_meta, &uuid,
				    &clnt_id);
	if (res != TEE_SUCCESS)
		goto out;

	res = copy_in_params(arg->params + num_meta, num_params - num_meta,
			     &param, saved_attr);
	if (res != TEE_SUCCESS)
		goto cleanup_shm_refs;

	res = tee_ta_open_session(&err_orig, &s, &tee_open_sessions, &uuid,
				  &clnt_id, TEE_TIMEOUT_INFINITE, &param);
	if (res != TEE_SUCCESS)
		s = NULL;
	copy_out_param(&param, num_params - num_meta, arg->params + num_meta,
		       saved_attr);

	/*
	 * The occurrence of open/close session command is usually
	 * un-predictable, using this property to increase randomness
	 * of prng
	 */
	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_SESSION,
				     &session_pnum);

cleanup_shm_refs:
	cleanup_shm_refs(saved_attr, &param, num_params - num_meta);

out:
	if (s)
		arg->session = s->id;
	else
		arg->session = 0;
	arg->ret = res;
	arg->ret_origin = err_orig;
}

static void entry_close_session(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	struct tee_ta_session *s;

	if (num_params) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_SESSION,
				     &session_pnum);

	s = tee_ta_find_session(arg->session, &tee_open_sessions);
	res = tee_ta_close_session(s, &tee_open_sessions, NSAPP_IDENTITY);
out:
	arg->ret = res;
	arg->ret_origin = TEE_ORIGIN_TEE;
}

static void entry_invoke_command(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s;
	struct tee_ta_param param = { 0 };
	uint64_t saved_attr[TEE_NUM_PARAMS] = { 0 };

	res = copy_in_params(arg->params, num_params, &param, saved_attr);
	if (res != TEE_SUCCESS)
		goto out;

	s = tee_ta_get_session(arg->session, true, &tee_open_sessions);
	if (!s) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = tee_ta_invoke_command(&err_orig, s, NSAPP_IDENTITY,
				    TEE_TIMEOUT_INFINITE, arg->func, &param);

	tee_ta_put_session(s);

	copy_out_param(&param, num_params, arg->params, saved_attr);

out:
	cleanup_shm_refs(saved_attr, &param, num_params);

	arg->ret = res;
	arg->ret_origin = err_orig;
}

static void entry_cancel(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s;

	if (num_params) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	s = tee_ta_get_session(arg->session, false, &tee_open_sessions);
	if (!s) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = tee_ta_cancel_command(&err_orig, s, NSAPP_IDENTITY);
	tee_ta_put_session(s);

out:
	arg->ret = res;
	arg->ret_origin = err_orig;
}

#ifndef CFG_CORE_FFA
#ifdef CFG_CORE_DYN_SHM
static void register_shm(struct optee_msg_arg *arg, uint32_t num_params)
{
	struct optee_msg_param_tmem *tmem = NULL;
	struct mobj *mobj = NULL;

	arg->ret = TEE_ERROR_BAD_PARAMETERS;

	if (num_params != 1 ||
	    (arg->params[0].attr !=
	     (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT | OPTEE_MSG_ATTR_NONCONTIG)))
		return;

	tmem = &arg->params[0].u.tmem;
	mobj = msg_param_mobj_from_noncontig(tmem->buf_ptr, tmem->size,
					     tmem->shm_ref, false);

	if (!mobj)
		return;

	mobj_reg_shm_unguard(mobj);
	arg->ret = TEE_SUCCESS;
}

static void unregister_shm(struct optee_msg_arg *arg, uint32_t num_params)
{
	if (num_params == 1) {
		uint64_t cookie = arg->params[0].u.rmem.shm_ref;
		TEE_Result res = mobj_reg_shm_release_by_cookie(cookie);

		if (res)
			EMSG("Can't find mapping with given cookie");
		arg->ret = res;
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
	}
}
#endif /*CFG_CORE_DYN_SHM*/
#endif

static void __maybe_unused lend_protmem(struct optee_msg_arg *arg,
					uint32_t num_params)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct optee_msg_param_tmem *tmem = NULL;
	struct mobj *mobj = NULL;
	uint64_t use_case = 0;
	uint64_t cookie = 0;
	paddr_size_t sz = 0;
	paddr_t pa = 0;

	if (num_params != 2 ||
	    READ_ONCE(arg->params[0].attr) != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT ||
	    READ_ONCE(arg->params[1].attr) != OPTEE_MSG_ATTR_TYPE_TMEM_INPUT)
		goto out;

	use_case = READ_ONCE(arg->params[0].u.value.a);
	tmem = &arg->params[1].u.tmem;
	cookie = READ_ONCE(tmem->shm_ref);
	pa = READ_ONCE(tmem->buf_ptr);
	sz = READ_ONCE(tmem->size);

	switch (use_case) {
	case MOBJ_USE_CASE_SEC_VIDEO_PLAY:
	case MOBJ_USE_CASE_TRUSED_UI:
		break;
	default:
		goto out;
	}
	mobj = mobj_protmem_alloc(pa, sz, cookie, use_case);
	if (mobj)
		res = TEE_SUCCESS;
out:
	arg->ret = res;
}

static void __maybe_unused assign_protmem(struct optee_msg_arg *arg,
					  uint32_t num_params)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint64_t use_case = 0;
	uint64_t cookie = 0;

	if (num_params != 1 ||
	    READ_ONCE(arg->params[0].attr) != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto out;

	cookie = READ_ONCE(arg->params[0].u.value.a);
	use_case = READ_ONCE(arg->params[0].u.value.b);
	res = mobj_ffa_assign_protmem(cookie, use_case);
out:
	arg->ret = res;
}

static void __maybe_unused reclaim_protmem(struct optee_msg_arg *arg,
					   uint32_t num_params)
{
	if (num_params == 1 &&
	    READ_ONCE(arg->params[0].attr) == OPTEE_MSG_ATTR_TYPE_RMEM_INPUT) {
		uint64_t cookie = READ_ONCE(arg->params[0].u.rmem.shm_ref);
		TEE_Result res = mobj_protmem_release_by_cookie(cookie);

		if (res)
			EMSG("Can't find mapping with cookie %#"PRIx64,
			     cookie);
		arg->ret = res;
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
	}
}

static void __maybe_unused get_protmem_config(struct optee_msg_arg *arg,
					      uint32_t num_params)
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	uint64_t saved_attr[TEE_NUM_PARAMS] = { 0 };
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct tee_ta_param param = { 0 };
	size_t min_mem_align = 0;
	size_t min_mem_sz = 0;
	uint64_t use_case = 0;
	void *buf = NULL;
	size_t sz = 0;

	arg->ret_origin = TEE_ORIGIN_TEE;

	if (num_params != 2)
		goto out;
	res = copy_in_params(arg->params, num_params, &param, saved_attr);
	if (res)
		goto out;
	if (param.types != exp_pt) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out_cleanup;
	}

	use_case = param.u[0].val.a;
	/* Check that it's not truncated when passed as an enum */
	if (use_case >= INT_MAX) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out_cleanup;
	}
	sz = param.u[1].mem.size;
	if (param.u[1].mem.mobj) {
		res = mobj_inc_map(param.u[1].mem.mobj);
		if (res)
			goto out_cleanup;
		buf = mobj_get_va(param.u[1].mem.mobj, param.u[1].mem.offs, sz);
		if (!buf) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out_dec_map;
		}
	}

	if (IS_ENABLED(CFG_CORE_FFA)) {
#ifdef CFG_CORE_FFA
		res = thread_spmc_get_protmem_config(use_case, buf, &sz,
						     &min_mem_sz,
						     &min_mem_align);
#else
		res = TEE_ERROR_NOT_SUPPORTED;
#endif
	} else {
		res = plat_get_protmem_config(use_case, &min_mem_sz,
					      &min_mem_align);
	}
	if (!res || res == TEE_ERROR_SHORT_BUFFER) {
		param.u[1].mem.size = sz;
		param.u[0].val.a = min_mem_sz;
		param.u[0].val.b = min_mem_align;
	}
	copy_out_param(&param, num_params, arg->params, saved_attr);
	arg->params[0].u.value.c = sizeof(long) * 8;

out_dec_map:
	mobj_dec_map(param.u[1].mem.mobj);
out_cleanup:
	cleanup_shm_refs(saved_attr, &param, num_params);
out:
	arg->ret = res;
}

void nsec_sessions_list_head(struct tee_ta_session_head **open_sessions)
{
	*open_sessions = &tee_open_sessions;
}

/* Note: this function is weak to let platforms add special handling */
TEE_Result __weak tee_entry_std(struct optee_msg_arg *arg, uint32_t num_params)
{
	return __tee_entry_std(arg, num_params);
}


// -------------------- TOTP

static int base32_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;  /* padding, whitespace, invalid */
}

static int base32_decode(const char *src, uint8_t *dst, int dstlen)
{
    uint64_t buf = 0;
    int bits = 0, out = 0;
    for (; *src; ++src) {
        int v = base32_val(*src);
        if (v < 0) continue;          /* skip '=' padding and spaces */
        buf = (buf << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            if (out >= dstlen) return -1;
            dst[out++] = (uint8_t)(buf >> (bits - 8));
            bits -= 8;
        }
    }
    return out;
}

/* ── SHA-1 (FIPS 180-4) — self-contained ───────────────────────────────── */

#define ROL32(x,n) (((uint32_t)(x)<<(n))|((uint32_t)(x)>>(32-(n))))

typedef struct {
    uint32_t h[5];
    uint8_t  buf[64];
    uint64_t len;
    int      fill;
} SHA1Ctx;

static void sha1_compress(SHA1Ctx *s)
{
    uint32_t w[80], a, b, c, d, e, t;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)s->buf[i*4+0]<<24 | (uint32_t)s->buf[i*4+1]<<16
             | (uint32_t)s->buf[i*4+2]<< 8 | (uint32_t)s->buf[i*4+3];
    for (i = 16; i < 80; i++)
        w[i] = ROL32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

    a=s->h[0]; b=s->h[1]; c=s->h[2]; d=s->h[3]; e=s->h[4];
    for (i = 0; i < 80; i++) {
        if      (i < 20) t = ROL32(a,5) + ((b&c)|(~b&d))       + e + 0x5A827999U + w[i];
        else if (i < 40) t = ROL32(a,5) + ( b^c^ d)             + e + 0x6ED9EBA1U + w[i];
        else if (i < 60) t = ROL32(a,5) + ((b&c)|(b&d)|(c&d))   + e + 0x8F1BBCDCU + w[i];
        else             t = ROL32(a,5) + ( b^c^ d)             + e + 0xCA62C1D6U + w[i];
        e=d; d=c; c=ROL32(b,30); b=a; a=t;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d; s->h[4]+=e;
}

static void sha1_init(SHA1Ctx *s)
{
    s->h[0]=0x67452301U; s->h[1]=0xEFCDAB89U;
    s->h[2]=0x98BADCFEU; s->h[3]=0x10325476U; s->h[4]=0xC3D2E1F0U;
    s->fill=0; s->len=0;
}

static void sha1_update(SHA1Ctx *s, const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) {
        s->buf[s->fill++] = data[i];
        s->len++;
        if (s->fill == 64) { sha1_compress(s); s->fill=0; }
    }
}

static void sha1_final(SHA1Ctx *s, uint8_t out[20])
{
    uint64_t bits = s->len * 8;
    uint8_t b = 0x80;
    sha1_update(s, &b, 1);
    b = 0;
    while (s->fill != 56) sha1_update(s, &b, 1);
    for (int i = 7; i >= 0; i--) { b=(uint8_t)(bits>>(i*8)); sha1_update(s,&b,1); }
    for (int i = 0; i < 5; i++) {
        out[i*4+0]=(uint8_t)(s->h[i]>>24); out[i*4+1]=(uint8_t)(s->h[i]>>16);
        out[i*4+2]=(uint8_t)(s->h[i]>> 8); out[i*4+3]=(uint8_t)(s->h[i]);
    }
}

/* ── HMAC-SHA1 (RFC 2104) ───────────────────────────────────────────────── */

static void hmac_sha1(const uint8_t *key, int klen,
                      const uint8_t *msg, int mlen,
                      uint8_t out[20])
{
    uint8_t k[64], ipad[64], opad[64], inner[20];
    SHA1Ctx s;

    memset(k, 0, 64);
    if (klen > 64) {
        sha1_init(&s); sha1_update(&s, key, klen); sha1_final(&s, k);
    } else {
        memcpy(k, key, klen);
    }
    for (int i = 0; i < 64; i++) { ipad[i] = k[i]^0x36; opad[i] = k[i]^0x5C; }

    sha1_init(&s);
    sha1_update(&s, ipad, 64);
    sha1_update(&s, msg,  mlen);
    sha1_final(&s, inner);

    sha1_init(&s);
    sha1_update(&s, opad,  64);
    sha1_update(&s, inner, 20);
    sha1_final(&s, out);
}

/* ── TOTP — the one function ────────────────────────────────────────────── */
/*
 * generate_totp()
 *
 *   secret  : Base32-encoded shared secret (e.g. from a Google Authenticator QR)
 *   digits  : code length, typically 6
 *   period  : time-step in seconds, typically 30
 *
 *   Returns : OTP value (>= 0), or -1 on error (bad secret).
 *             The caller should zero-pad to `digits` when printing.
 */
static int generate_totp(const char *secret, int times, int digits, int period)
{
    /* 1. Decode the Base32 secret into raw bytes */
    uint8_t key[64];
    int klen = base32_decode(secret, key, (int)sizeof(key));
    if (klen <= 0) return -1;

    /* 2. Counter T = floor(Unix timestamp / period) as big-endian 8 bytes */
    uint64_t T = (uint64_t)times / (uint64_t)period;
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (uint8_t)(T & 0xFF); T >>= 8; }

    /* 3. HMAC-SHA1(key, T) → 20-byte digest */
    uint8_t hmac[20];
    hmac_sha1(key, klen, msg, 8, hmac);

    /* 4. Dynamic truncation: pick 4 bytes at offset = low nibble of last byte */
    int offset = hmac[19] & 0x0F;
    uint32_t bin = ((uint32_t)(hmac[offset  ] & 0x7F) << 24)
                 | ((uint32_t)(hmac[offset+1] & 0xFF) << 16)
                 | ((uint32_t)(hmac[offset+2] & 0xFF) <<  8)
                 | ((uint32_t)(hmac[offset+3] & 0xFF));

    /* 5. Reduce to the requested number of digits */
    static const uint32_t POW10[] = {
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
    };
    return (int)(bin % POW10[digits]);
}


static void __maybe_unused test_yielding(struct optee_msg_arg *arg,
					   uint32_t num_params)
{
	const char *SECRET = "JBSWY3DPEHPK3PXP";
	const int   DIGITS = 6;
	const int   PERIOD = 5;   /* seconds */

	arg->ret = TEE_SUCCESS;
	char *c = phys_to_virt(0x08000010, MEM_AREA_NSEC_SHM, 8);
	uint64_t t = arg->params[0].u.value.a;
	int code = generate_totp(SECRET, t, DIGITS, PERIOD);
	arg->params[0].u.value.a = code;
}

// RSA

/* c^d mod n, with 128-bit intermediates -> works for any modulus n < 2^64 */
static uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod)
{
	unsigned __int128 r = 1, b = base % mod;
	while (exp) {
		if (exp & 1)
			r = (r * b) % mod;
		b = (b * b) % mod;
		exp >>= 1;
	}
	return (uint64_t)r;
}

/*static void rsa_decrypt(struct optee_msg_arg *arg, uint32_t num_params)*/
/*{*/
	/*[> PRIVATE KEY — never leaves OP-TEE. (demo values: p=61,q=53,e=17) <]*/
	/*static const uint64_t d = 2753; [> private exponent <]*/
	/*static const uint64_t n = 3233; [> modulus          <]*/

	/*if (num_params != 1) {*/
		/*arg->ret = TEE_ERROR_BAD_PARAMETERS;*/
		/*return;*/
	/*}*/
	/*arg->params[0].u.value.a = modexp(arg->params[0].u.value.a, d, n);*/
	/*arg->ret = TEE_SUCCESS;*/
/*}*/
#include <crypto/crypto.h>
#include <mm/core_memprot.h>
#include <utee_defines.h>        /* TEE_INTERNAL_HASH_TO_ALGO */
#include <tee_api_defines.h>     /* TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 */

/* PRIVATE KEY — big-endian bytes, compiled into OP-TEE, never output.
 * n and e are public; d (and any CRT params) are the secret that stays here. */
static const uint8_t RSA_E[3]   = { 0x01, 0x00, 0x01 };   /* 65537 */
static const uint8_t RSA_N[256] = {
    0xd3, 0x1d, 0xac, 0xbb, 0x3c, 0xb3, 0x05, 0x2b, 0xd5, 0xe4, 0xe0, 0x6f, 
    0xbe, 0xe9, 0xf6, 0x41, 0xba, 0x44, 0xe8, 0x66, 0xab, 0x36, 0x0d, 0x46, 
    0xdf, 0xda, 0x9a, 0x3e, 0xa9, 0xc3, 0x14, 0xbd, 0xae, 0x52, 0xbf, 0x28, 
    0xa2, 0xb7, 0x49, 0xbe, 0x66, 0x2e, 0x6d, 0xce, 0x28, 0xab, 0xf5, 0xb2, 
    0x00, 0x12, 0xa2, 0x78, 0x75, 0x01, 0xf9, 0x63, 0x2e, 0x31, 0x33, 0xae, 
    0x1b, 0xf9, 0x55, 0x96, 0x3a, 0x3e, 0x6a, 0xc7, 0x7d, 0xfb, 0xd7, 0xfd, 
    0xb2, 0xa8, 0xb9, 0x90, 0x6f, 0x62, 0xd5, 0x87, 0x94, 0x1e, 0xb8, 0x2c, 
    0x45, 0x70, 0x85, 0x29, 0x16, 0x36, 0xa7, 0xd2, 0x71, 0xb9, 0x8f, 0x0c, 
    0xad, 0x8e, 0x9a, 0x42, 0x4e, 0x65, 0xf4, 0xb0, 0x04, 0xe0, 0xab, 0x34, 
    0xdb, 0x46, 0xdb, 0x00, 0x6e, 0x71, 0xb6, 0x8b, 0x6a, 0x5e, 0xe2, 0x6f, 
    0x4f, 0xc5, 0x6e, 0xd0, 0xfa, 0x7e, 0x5b, 0xda, 0xa9, 0x20, 0xf8, 0xa3, 
    0x3a, 0x60, 0x17, 0x16, 0x48, 0xf1, 0xd7, 0xc1, 0x42, 0x1d, 0xe8, 0xbd, 
    0xe1, 0x91, 0xda, 0x94, 0x9d, 0x9d, 0xf6, 0x18, 0x7f, 0x2c, 0x41, 0x2b, 
    0x2f, 0x1d, 0x28, 0x1d, 0xdf, 0xe9, 0x99, 0xbf, 0x9c, 0xad, 0x25, 0x8a, 
    0x00, 0x2d, 0x39, 0x26, 0xe4, 0x2d, 0x6d, 0xc2, 0x11, 0xeb, 0xea, 0x27, 
    0x47, 0x62, 0x0e, 0x35, 0x6a, 0x8f, 0x83, 0xee, 0x7a, 0x7a, 0xab, 0x8d, 
    0xd7, 0xbe, 0xfe, 0x90, 0x98, 0xc2, 0x65, 0x22, 0x08, 0x27, 0x8b, 0x98, 
    0xde, 0x0f, 0x4d, 0x36, 0x2b, 0xe1, 0x40, 0xf5, 0xfc, 0xa2, 0xc9, 0x13, 
    0x48, 0xd0, 0xde, 0x53, 0xc2, 0x04, 0x23, 0x4f, 0x7b, 0x23, 0xa9, 0xf8, 
    0x52, 0x42, 0xca, 0x70, 0x3a, 0xcd, 0xed, 0xb6, 0xc7, 0xfd, 0xf0, 0x82, 
    0x9c, 0x05, 0x42, 0x4c, 0xdc, 0x99, 0x86, 0xf9, 0x57, 0xc6, 0x47, 0x08, 
    0xf2, 0xe3, 0x17, 0x53, 
};
static const uint8_t RSA_D[256] = {
    0x1e, 0x71, 0xda, 0x16, 0x0a, 0x53, 0xda, 0xbc, 0x0e, 0x95, 0x7a, 0x14, 
    0x43, 0x58, 0xe4, 0x0d, 0x68, 0x7a, 0x45, 0x75, 0x80, 0xdd, 0x43, 0x9e, 
    0xe3, 0xeb, 0x57, 0x71, 0x0f, 0xf4, 0x35, 0x0a, 0x81, 0x98, 0x27, 0x3f, 
    0x09, 0xf0, 0x1a, 0xaf, 0x5d, 0x76, 0xf6, 0x98, 0xd3, 0x5e, 0xb1, 0x08, 
    0xe1, 0x5f, 0xce, 0x94, 0x46, 0x73, 0x69, 0x6e, 0x77, 0x1b, 0xdb, 0x53, 
    0x11, 0x6f, 0xac, 0x7b, 0x04, 0x9d, 0x39, 0xb2, 0xd9, 0x25, 0x37, 0x69, 
    0xbb, 0x98, 0xff, 0x61, 0xa7, 0xde, 0x7d, 0xe2, 0x96, 0x66, 0xb3, 0xb2, 
    0x96, 0xb4, 0xfa, 0x4f, 0x09, 0x88, 0x0a, 0x3d, 0x9b, 0xee, 0xe1, 0x85, 
    0x37, 0x86, 0x28, 0x12, 0xc5, 0xd1, 0x88, 0x2e, 0xd6, 0x15, 0x3c, 0x3b, 
    0x5c, 0x1f, 0xe4, 0xb7, 0x34, 0x36, 0x2b, 0xd8, 0x01, 0x17, 0xfb, 0xd9, 
    0x87, 0x8c, 0x76, 0x45, 0xa6, 0xca, 0x10, 0x1e, 0xbe, 0x47, 0x81, 0x99, 
    0x98, 0xf2, 0x1b, 0x3f, 0x5d, 0xe6, 0xf9, 0xb2, 0x41, 0x4a, 0x75, 0xb3, 
    0x79, 0x68, 0x6b, 0x49, 0xd8, 0x95, 0x8f, 0x85, 0x58, 0xd4, 0xde, 0x77, 
    0x07, 0x8c, 0x8d, 0xe3, 0x27, 0x31, 0x6d, 0x00, 0xc3, 0x54, 0x11, 0x8d, 
    0x13, 0x12, 0x4b, 0x86, 0x82, 0x4e, 0xc8, 0x98, 0x9e, 0x47, 0x8d, 0xee, 
    0x64, 0xde, 0xe9, 0x53, 0xdf, 0x6c, 0xc5, 0x1d, 0x53, 0xff, 0xa4, 0x8b, 
    0x5c, 0x15, 0x12, 0xd7, 0x92, 0xd9, 0x6e, 0xd7, 0xdb, 0xa7, 0x54, 0x73, 
    0xda, 0xce, 0x43, 0x98, 0xe7, 0xd7, 0x75, 0xba, 0x39, 0xc3, 0x54, 0x65, 
    0x42, 0xb2, 0xa6, 0xcc, 0x5e, 0xb2, 0x12, 0x96, 0xbd, 0x6d, 0x77, 0x15, 
    0xf9, 0x6d, 0x58, 0x71, 0x7e, 0x38, 0x21, 0x9f, 0xf4, 0x89, 0x49, 0x56, 
    0x8b, 0x80, 0x2a, 0x40, 0x99, 0x8f, 0x6f, 0x80, 0x20, 0x82, 0xb7, 0xd7, 
    0x28, 0x3a, 0x4f, 0x51, 
};

static void rsa_decrypt(struct optee_msg_arg *arg, uint32_t num_params)
{
	struct rsa_keypair key = { };
	uint8_t *ct, *pt;
	size_t ct_len, pt_len = 256;
	TEE_Result res;

	if (num_params != 1) { arg->ret = TEE_ERROR_BAD_PARAMETERS; return; }

	ct_len = arg->params[0].u.value.a;                 /* ciphertext length in */
	ct = phys_to_virt(0x08001000, MEM_AREA_NSEC_SHM, ct_len); /* ct in SHM  */
	pt = phys_to_virt(0x08002000, MEM_AREA_NSEC_SHM, 256);    /* pt out SHM */
	if (!ct || !pt) { arg->ret = TEE_ERROR_BAD_PARAMETERS; return; }

	res = crypto_acipher_alloc_rsa_keypair(&key, 2048);
	if (res) { arg->ret = res; return; }

	if (crypto_bignum_bin2bn(RSA_N, sizeof(RSA_N), key.n) ||
			crypto_bignum_bin2bn(RSA_E, sizeof(RSA_E), key.e) ||
			crypto_bignum_bin2bn(RSA_D, sizeof(RSA_D), key.d)) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	res = crypto_acipher_rsaes_decrypt(
			TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, &key,
			NULL, 0,                                   /* OAEP label (none) */
			TEE_INTERNAL_HASH_TO_ALGO(TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256),
			ct, ct_len, pt, &pt_len);

	arg->params[0].u.value.a = pt_len;     /* plaintext length out; data in SHM */
out:
	crypto_acipher_free_rsa_keypair(&key);
	arg->ret = res;
}



/*
 * If tee_entry_std() is overridden, it's still supposed to call this
 * function.
 */
TEE_Result __tee_entry_std(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res = TEE_SUCCESS;

	/* Enable foreign interrupts for STD calls */
	thread_set_foreign_intr(true);
	switch (arg->cmd) {
	case OPTEE_MSG_CMD_OPEN_SESSION:
		entry_open_session(arg, num_params);
		break;
	case OPTEE_MSG_CMD_CLOSE_SESSION:
		entry_close_session(arg, num_params);
		break;
	case OPTEE_MSG_CMD_INVOKE_COMMAND:
		entry_invoke_command(arg, num_params);
		break;
	case OPTEE_MSG_CMD_CANCEL:
		entry_cancel(arg, num_params);
		break;
	case OPTEE_MSG_CMD_TEST_Y:
		test_yielding(arg, num_params);
		break;
	case OPTEE_MSG_CMD_RSA_DEC:
		rsa_decrypt(arg, num_params);
		break;
#if defined(CFG_CORE_DYN_SHM) && !defined(CFG_CORE_FFA)
	case OPTEE_MSG_CMD_REGISTER_SHM:
		register_shm(arg, num_params);
		break;
	case OPTEE_MSG_CMD_UNREGISTER_SHM:
		unregister_shm(arg, num_params);
		break;
#endif
	case OPTEE_MSG_CMD_DO_BOTTOM_HALF:
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			notif_deliver_event(NOTIF_EVENT_DO_BOTTOM_HALF);
		else
			goto err;
		break;
	case OPTEE_MSG_CMD_STOP_ASYNC_NOTIF:
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			notif_deliver_event(NOTIF_EVENT_STOPPED);
		else
			goto err;
		break;
#ifdef CFG_CORE_DYN_PROTMEM
	case OPTEE_MSG_CMD_GET_PROTMEM_CONFIG:
		get_protmem_config(arg, num_params);
		break;
#ifdef CFG_CORE_FFA
	case OPTEE_MSG_CMD_ASSIGN_PROTMEM:
		assign_protmem(arg, num_params);
		break;
#else
	case OPTEE_MSG_CMD_LEND_PROTMEM:
		lend_protmem(arg, num_params);
		break;
	case OPTEE_MSG_CMD_RECLAIM_PROTMEM:
		reclaim_protmem(arg, num_params);
#endif /*!CFG_CORE_FFA*/
#endif /*CFG_CORE_DYN_PROTMEM*/
	default:
err:
		EMSG("Unknown cmd 0x%x", arg->cmd);
		res = TEE_ERROR_NOT_IMPLEMENTED;
	}

	return res;
}

static TEE_Result default_mobj_init(void)
{
#ifdef CFG_CORE_RESERVED_SHM
	shm_mobj = mobj_phys_alloc(default_nsec_shm_paddr,
				   default_nsec_shm_size, SHM_CACHE_ATTRS,
				   CORE_MEM_NSEC_SHM);
	if (!shm_mobj)
		panic("Failed to register shared memory");
#endif

#ifdef CFG_SECURE_DATA_PATH
	sdp_mem_mobjs = core_sdp_mem_create_mobjs();
	if (!sdp_mem_mobjs)
		panic("Failed to register SDP memory");
#endif

	return TEE_SUCCESS;
}


driver_init_late(default_mobj_init);
