
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "OpenIPMI.h"

swig_cb
ref_swig_cb(swig_cb cb)
{
    SV *ref = cb;

    SvREFCNT_inc(ref);
    return cb;
}

swig_cb
deref_swig_cb(swig_cb cb)
{
    SV *ref = cb;

    SvREFCNT_dec(ref);
    return cb;
}

void
swig_call_cb(swig_cb cb, char *method_name,
	     char *format, ...)
{
    SV *ref = cb;
    va_list ap;
    dSP ;

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
	    XPUSHs(va_arg(ap, SV *));
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
swig_make_ref(void *item, char *class)
{
    SV *ref = newSV(0);

    return sv_setref_pv(ref, class, item);
}

void swig_free_ref(swig_ref ref)
{
    SvREFCNT_dec(ref);
}
