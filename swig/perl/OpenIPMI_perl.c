
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "OpenIPMI.h"

swig_cb_val
get_swig_cb(swig_cb cb)
{
    swig_cb_val rv = SvRV(cb);
    return rv;
}

swig_cb_val
ref_swig_cb(swig_cb cb)
{
    swig_cb_val rv = SvRV(cb);

    SvREFCNT_inc(rv);
    return rv;
}

swig_cb_val
deref_swig_cb(swig_cb cb)
{
    swig_cb_val rv = SvRV(cb);

    SvREFCNT_dec(rv);
    return rv;
}

swig_cb_val
deref_swig_cb_val(swig_cb_val cb)
{
    SvREFCNT_dec(cb);
    return cb;
}

void
swig_call_cb(swig_cb_val cb, char *method_name,
	     char *format, ...)
{
    SV            *ref = newRV_inc(cb);
    va_list       ap;
    int           len;
    unsigned char *data;
    dSP ;

    sv_bless(ref, SvSTASH(cb));

    ENTER;
    SAVETMPS;

    va_start(ap, format);

    PUSHMARK(SP);
    XPUSHs(ref);
    for (; *format; format++) {
	if (*format != '%')
	    continue;
	format++;
	if (*format == '\0')
	    break;
	switch (*format) {
	case 'd':
	    XPUSHs(sv_2mortal(newSViv(va_arg(ap, int))));
	    break;

	case 'f':
	    XPUSHs(sv_2mortal(newSVnv(va_arg(ap, double))));
	    break;

	case '*':
	    format++;
	    if (*format == '\0')
		break;
	    switch(*format) {
	    case 's':
		/* An array of unsigned characters */
		len = va_arg(ap, int);
		data = va_arg(ap, unsigned char *);
		while (len > 0) {
		    XPUSHs(sv_2mortal(newSViv(*data)));
		    data++;
		    len--;
		}
		break;

	    default:
		break;
	    }
	    break;

	case 'l':
	    format++;
	    if (*format == '\0')
		break;
	    switch(*format) {
	    case 'd':
		XPUSHs(sv_2mortal(newSViv(va_arg(ap, long))));
		break;

	    default:
		break;
	    }
	    break;
	    
	case 's':
	    XPUSHs(sv_2mortal(newSVpv(va_arg(ap, char *), 0)));
	    break;

	case 'p':
	    XPUSHs(va_arg(ap, swig_ref *)->val);
	    break;

	default:
	    break;
	}
    }
    PUTBACK;

    va_end(ap);

    call_method(method_name, G_DISCARD);

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(ref);
}

swig_ref
swig_make_ref_destruct(void *item, char *class)
{
    SV *self;
    SV *obj=newSV(0);
    HV *hash=newHV();
    HV *stash;
    swig_ref rv;
    HV *hv;
    GV *gv;
 
    rv.val = newSV(0);
    sv_setref_pv(obj, class, item);
    stash=SvSTASH(SvRV(obj));

    gv=*(GV**)hv_fetch(stash, "OWNER", 5, TRUE);
    if (!isGV(gv))
	gv_init(gv, stash, "OWNER", 5, FALSE);
    hv=GvHVn(gv);
    hv_store_ent(hv, obj, newSViv(1), 0);

    sv_magic((SV *)hash, (SV *)obj, 'P', Nullch, 0);
    SvREFCNT_dec(obj);
    self=newRV_noinc((SV *)hash);
    sv_setsv(rv.val, self);
    SvREFCNT_dec((SV *)self);
    sv_bless(rv.val, stash);
    return rv;
}

swig_ref
swig_make_ref(void *item, char *class)
{
    SV *ref = newSV(0);
    swig_ref rv;

    rv.val = sv_setref_pv(ref, class, item);
    return rv;
}

void swig_free_ref(swig_ref ref)
{
    SvREFCNT_dec(ref.val);
}
