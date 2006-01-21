/*
 * OpenIPMI_lang.i
 *
 * Perl-specific OpenIPMI SWIG language information
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

%typemap(in) swig_cb {
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    $1 = $input;
}

%typemap(arginit) intarray {
    $1.val = NULL;
}

%typemap(in) intarray {
    AV *tempav;
    I32 len;
    int i;
    SV  **tv;
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    if (SvTYPE(SvRV($input)) != SVt_PVAV)
	croak("Argument $argnum is not an array.");
    tempav = (AV*)SvRV($input);
    len = av_len(tempav);
    $1.val = (int *) malloc((len+2)*sizeof(int));
    $1.len = len + 1;
    
    for (i = 0; i <= len; i++) {
	tv = av_fetch(tempav, i, 0);
	$1.val[i] = SvIV(*tv);
    }
}

%typemap(freearg) intarray {
    if ($1.val)
        free($1.val);
};

%typemap(out) intarray {
    AV *tempav;
    SV **svs;
    int i;

    svs = (SV **) malloc($1.len*sizeof(SV *));
    for (i=0; i<$1.len; i++) {
	svs[i] = sv_newmortal();
	sv_setiv(svs[i], $1.val[i]);
    }
    tempav = av_make($1.len, svs);
    free(svs);
    $result = newRV((SV *) tempav);
    sv_2mortal($result);
    argvi++;
}

%typemap(in) argarray * (argarray argval) {
    AV *tempav;
    int i;
    SV  **tv;
    $1 = &argval;
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    if (SvTYPE(SvRV($input)) != SVt_PVAV)
	croak("Argument $argnum is not an array.");
    tempav = (AV*)SvRV($input);
    $1->len = av_len(tempav) + 1;
    $1->val = malloc(($1->len)*sizeof(char *));
    for (i = 0; i < $1->len; i++) {
	tv = av_fetch(tempav, i, 0);
	$1->val[i] = (char *) SvPV(*tv,PL_na);
    }
};

%typemap(out) argarray * {
    /* Nothing to do, input only */
};

%typemap(freearg) argarray * {
    free($1->val);
};

%typemap(in) iargarray * (iargarray argval) {
    AV *tempav;
    int i;
    SV  **tv;
    $1 = &argval;
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    if (SvTYPE(SvRV($input)) != SVt_PVAV)
	croak("Argument $argnum is not an array.");
    tempav = (AV*)SvRV($input);
    $1->len = av_len(tempav) + 1;
    $1->val = malloc(($1->len)*sizeof(char *));
    for (i = 0; i < $1->len; i++) {
	tv = av_fetch(tempav, i, 0);
        if (SWIG_ConvertPtr(*tv, (void **) &($1->val[i]),
			    SWIGTYPE_p_ipmi_args_t,0) < 0)
            SWIG_croak("Type error. Expected _p_ipmi_args_t");
	if (! $1->val[i])
            SWIG_croak("Type error. NULL not allowed for _p_ipmi_args_t");
    }
};

%typemap(out) iargarray * {
    /* Nothing to do, input only */
};

%typemap(freearg) iargarray * {
    free($1->val);
};

%typemap(in) strconstarray * (strconstarray argval) {
    $1 = &argval;
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    if (SvTYPE(SvRV($input)) != SVt_PVAV)
	croak("Argument $argnum is not an array.");
    $1->len = 0;
    $1->val = NULL;
};

%typemap(out) strconstarray * {
    AV *tempav;
    SV **svs;
    int i;

    svs = (SV **) malloc($1->len*sizeof(SV *));
    for (i=0; i<$1->len; i++) {
	svs[i] = sv_newmortal();
	sv_setpv(svs[i], $1->val[i]);
    }
    tempav = av_make($1->len, svs);
    free(svs);
    $result = newRV((SV *) tempav);
    sv_2mortal($result);
    argvi++;
};

%typemap(freearg) strconstarray * {
    free($1->val);
};

%typemap(in) double * (double dvalue) {
    SV* tempsv;
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    tempsv = SvRV($input);
    if ((!SvNOK(tempsv)) && (!SvIOK(tempsv))) {
	dvalue = 0.0;
    } else {
	dvalue = SvNV(tempsv);
    }
    $1 = &dvalue;
}

%typemap(argout) double * {
    SV *tempsv;
    tempsv = SvRV($input);
    sv_setnv(tempsv, *$1);
}

%typemap(in) int * (int ivalue) {
    SV* tempsv;
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    tempsv = SvRV($input);
    if (!SvIOK(tempsv)) {
	ivalue = 0;
    } else {
	ivalue = SvIV(tempsv);
    }
    $1 = &ivalue;
}

%typemap(argout) int * {
    SV *tempsv;
    tempsv = SvRV($input);
    sv_setiv(tempsv, *$1);
}

%typemap(in) unsigned int * (unsigned int ivalue) {
    SV* tempsv;
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    tempsv = SvRV($input);
    if (!SvIOK(tempsv)) {
	ivalue = 0;
    } else {
	ivalue = SvIV(tempsv);
    }
    $1 = &ivalue;
}

%typemap(argout) unsigned int * {
    SV *tempsv;
    tempsv = SvRV($input);
    sv_setiv(tempsv, *$1);
}

%typemap(in) const char ** (char *svalue) {
    SV* tempsv;
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    tempsv = SvRV($input);
    if (!SvOK(tempsv)) {
	svalue = NULL;
    } else {
	svalue = SvPV_nolen(tempsv);
    }
    $1 = &svalue;
}

%typemap(argout) const char ** {
    SV *tempsv;
    tempsv = SvRV($input);
    sv_setpv(tempsv, *$1);
}

%typemap(in) char ** (char *svalue) {
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    svalue = NULL;
    $1 = &svalue;
}

%typemap(argout) char ** {
    SV *tempsv;
    tempsv = SvRV($input);
    sv_setpv(tempsv, *$1);
    free(*$1);
}

%typemap(in) ipmi_fru_node_t ** (ipmi_fru_node_t *pvalue) {
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    pvalue = NULL;
    $1 = &pvalue;
}

%typemap(argout) ipmi_fru_node_t ** {
    SV *tempsv;
    if (*$1) {
	tempsv = SvRV($input);
	SWIG_MakePtr(tempsv, *$1, SWIGTYPE_p_ipmi_fru_node_t,
		     SWIG_SHADOW|SWIG_OWNER);
    }
}

%typemap(in) charbuf {
    SV* tempsv;
    if (!SvROK($input)) {
	croak("expected a reference\n");
    }
    tempsv = SvRV($input);
    if (!SvOK(tempsv)) {
	$1.val = NULL;
	$1.len = 0;
    } else {
	$1.val = SvPV(tempsv, $1.len);
    }
}

%typemap(out) charbuf {
    /* Nothing to do, input only */
};

%{
#if PERL_HAS_POSIX_THREADS
#define USE_POSIX_THREADS
#endif

static swig_ref
swig_make_ref_destruct_i(void *item, swig_type_info *class)
{
    swig_ref rv;

    rv.val = newSV(0);
    SWIG_MakePtr(rv.val, item, class, SWIG_SHADOW | SWIG_OWNER);
    return rv;
}

/* Make a reference whose destructor will be called when everything
   is done with it. */
#define swig_make_ref_destruct(item, name) \
	swig_make_ref_destruct_i(item, SWIGTYPE_p_ ## name)

static swig_ref
swig_make_ref_i(void *item, swig_type_info *class)
{
    swig_ref rv;

    rv.val = newSV(0);
    SWIG_MakePtr(rv.val, item, class, 0);
    return rv;
}

#define swig_make_ref(item, name) \
	swig_make_ref_i(item, SWIGTYPE_p_ ## name)

#define swig_free_ref_check(r, c) \
	do {								\
	    if (SvREFCNT(SvRV(r.val)) != 1)				\
		warn("***You cannot keep pointers of class OpenIPMI::%s", #c);\
	    swig_free_ref(r);						\
	} while(0)

/* Get the underlying callback object reference. */
static swig_cb_val
get_swig_cb_i(swig_cb cb)
{
    swig_cb_val rv = SvRV(cb);
    return rv;
}
#define get_swig_cb(cb, func) get_swig_cb_i(cb)

/* Get the underlying callback object reference and increment its refcount. */
static swig_cb_val
ref_swig_cb_i(swig_cb cb)
{
    swig_cb_val rv = SvRV(cb);

    SvREFCNT_inc(rv);
    return rv;
}
#define ref_swig_cb(cb, func) ref_swig_cb_i(cb)
#define ref_swig_2cb(cb, func, func2) ref_swig_cb_i(cb)
#define ref_swig_gencb(cb) ref_swig_cb_i(cb)

/* Get the underlying callback object reference and decrement its refcount. */
static swig_cb_val
deref_swig_cb(swig_cb cb)
{
    swig_cb_val rv = SvRV(cb);

    SvREFCNT_dec(rv);
    return rv;
}

/* Decrement the underlying callback object refcount. */
static swig_cb_val
deref_swig_cb_val(swig_cb_val cb)
{
    SvREFCNT_dec(cb);
    return cb;
}

static void
swig_free_ref(swig_ref ref)
{
    SvREFCNT_dec(ref.val);
}

/* Not required in Perl, no special C entry or exit handling required
   for functions that handle callbacks or might block. */
#define IPMI_SWIG_C_CB_ENTRY 
#define IPMI_SWIG_C_CB_EXIT 
#define IPMI_SWIG_C_BLOCK_ENTRY
#define IPMI_SWIG_C_BLOCK_EXIT

%}

