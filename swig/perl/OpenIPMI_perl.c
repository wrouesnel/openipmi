/*
 * OpenIPMI_perl.c
 *
 * Perl-specific routines for SWIG/OpenIPMI
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
    int           *idata;
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

	    case 'p':
		/* An array of integers */
		len = va_arg(ap, int);
		idata = va_arg(ap, int *);
		while (len > 0) {
		    XPUSHs(sv_2mortal(newSViv(*idata)));
		    idata++;
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
	    {
		swig_ref *v = va_arg(ap, swig_ref *);
		XPUSHs(v->val);
	    }
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
    SV *obj;
    HV *hash;
    HV *stash;
    swig_ref rv;
    HV *hv;
    GV *gv;

    if (!item)
	return swig_make_ref(item, class);
	
    obj=newSV(0);
    hash=newHV();
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
