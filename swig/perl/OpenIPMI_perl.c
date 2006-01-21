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

	    case 'b':
		/* An array of bytes as characters */
		len = va_arg(ap, size_t);
		XPUSHs(sv_2mortal(newSVpv(va_arg(ap, void *), len)));
		break;

	    case 'o':
		/* An array of objects */
		{
		    swig_ref *list;
		    len = va_arg(ap, int);
		    list = va_arg(ap, swig_ref *);
		    while (len > 0) {
			XPUSHs(list->val);
			list++;
			len--;
		    }
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
