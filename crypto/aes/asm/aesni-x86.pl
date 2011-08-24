#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# This module implements support for Intel AES-NI extension. In
# OpenSSL context it's used with Intel engine, but can also be used as
# drop-in replacement for crypto/aes/asm/aes-586.pl [see below for
# details].
#
# Performance.
#
# To start with see corresponding paragraph in aesni-x86_64.pl...
# Instead of filling table similar to one found there I've chosen to
# summarize *comparison* results for raw ECB, CTR and CBC benchmarks.
# The simplified table below represents 32-bit performance relative
# to 64-bit one in every given point. Ratios vary for different
# encryption modes, therefore interval values.
#
#	16-byte     64-byte     256-byte    1-KB        8-KB
#	53-67%      67-84%      91-94%      95-98%      97-99.5%
#
# Lower ratios for smaller block sizes are perfectly understandable,
# because function call overhead is higher in 32-bit mode. Largest
# 8-KB block performance is virtually same: 32-bit code is less than
# 1% slower for ECB, CBC and CCM, and ~3% slower otherwise.

# January 2011
#
# See aesni-x86_64.pl for details. Unlike x86_64 version this module
# interleaves at most 6 aes[enc|dec] instructions, because there are
# not enough registers for 8x interleave [which should be optimal for
# Sandy Bridge]. Actually, performance results for 6x interleave
# factor presented in aesni-x86_64.pl (except for CTR) are for this
# module.

$PREFIX="aesni";	# if $PREFIX is set to "AES", the script
			# generates drop-in replacement for
			# crypto/aes/asm/aes-586.pl:-)
$inline=1;		# inline _aesni_[en|de]crypt

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],$0);

if ($PREFIX eq "aesni")	{ $movekey=*movups; }
else			{ $movekey=*movups; }

$len="eax";
$rounds="ecx";
$key="edx";
$inp="esi";
$out="edi";
$rounds_="ebx";	# backup copy for $rounds
$key_="ebp";	# backup copy for $key

$rndkey0="xmm0";
$rndkey1="xmm1";
$inout0="xmm2";
$inout1="xmm3";
$inout2="xmm4";
$inout3="xmm5";	$in1="xmm5";
$inout4="xmm6";	$in0="xmm6";
$inout5="xmm7";	$ivec="xmm7";

# AESNI extenstion
sub aeskeygenassist
{ my($dst,$src,$imm)=@_;
    if ("$dst:$src" =~ /xmm([0-7]):xmm([0-7])/)
    {	&data_byte(0x66,0x0f,0x3a,0xdf,0xc0|($1<<3)|$2,$imm);	}
}
sub aescommon
{ my($opcodelet,$dst,$src)=@_;
    if ("$dst:$src" =~ /xmm([0-7]):xmm([0-7])/)
    {	&data_byte(0x66,0x0f,0x38,$opcodelet,0xc0|($1<<3)|$2);}
}
sub aesimc	{ aescommon(0xdb,@_); }
sub aesenc	{ aescommon(0xdc,@_); }
sub aesenclast	{ aescommon(0xdd,@_); }
sub aesdec	{ aescommon(0xde,@_); }
sub aesdeclast	{ aescommon(0xdf,@_); }

# Inline version of internal aesni_[en|de]crypt1
{ my $sn;
sub aesni_inline_generate1
{ my ($p,$inout,$ivec)=@_; $inout=$inout0 if (!defined($inout));
  $sn++;

    &$movekey		($rndkey0,&QWP(0,$key));
    &$movekey		($rndkey1,&QWP(16,$key));
    &xorps		($ivec,$rndkey0)	if (defined($ivec));
    &lea		($key,&DWP(32,$key));
    &xorps		($inout,$ivec)		if (defined($ivec));
    &xorps		($inout,$rndkey0)	if (!defined($ivec));
    &set_label("${p}1_loop_$sn");
	eval"&aes${p}	($inout,$rndkey1)";
	&dec		($rounds);
	&$movekey	($rndkey1,&QWP(0,$key));
	&lea		($key,&DWP(16,$key));
    &jnz		(&label("${p}1_loop_$sn"));
    eval"&aes${p}last	($inout,$rndkey1)";
}}

sub aesni_generate1	# fully unrolled loop
{ my ($p,$inout)=@_; $inout=$inout0 if (!defined($inout));

    &function_begin_B("_aesni_${p}rypt1");
	&movups		($rndkey0,&QWP(0,$key));
	&$movekey	($rndkey1,&QWP(0x10,$key));
	&xorps		($inout,$rndkey0);
	&$movekey	($rndkey0,&QWP(0x20,$key));
	&lea		($key,&DWP(0x30,$key));
	&cmp		($rounds,11);
	&jb		(&label("${p}128"));
	&lea		($key,&DWP(0x20,$key));
	&je		(&label("${p}192"));
	&lea		($key,&DWP(0x20,$key));
	eval"&aes${p}	($inout,$rndkey1)";
	&$movekey	($rndkey1,&QWP(-0x40,$key));
	eval"&aes${p}	($inout,$rndkey0)";
	&$movekey	($rndkey0,&QWP(-0x30,$key));
    &set_label("${p}192");
	eval"&aes${p}	($inout,$rndkey1)";
	&$movekey	($rndkey1,&QWP(-0x20,$key));
	eval"&aes${p}	($inout,$rndkey0)";
	&$movekey	($rndkey0,&QWP(-0x10,$key));
    &set_label("${p}128");
	eval"&aes${p}	($inout,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0,$key));
	eval"&aes${p}	($inout,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x10,$key));
	eval"&aes${p}	($inout,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0x20,$key));
	eval"&aes${p}	($inout,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x30,$key));
	eval"&aes${p}	($inout,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0x40,$key));
	eval"&aes${p}	($inout,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x50,$key));
	eval"&aes${p}	($inout,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0x60,$key));
	eval"&aes${p}	($inout,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x70,$key));
	eval"&aes${p}	($inout,$rndkey1)";
    eval"&aes${p}last	($inout,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt1");
}

# void $PREFIX_encrypt (const void *inp,void *out,const AES_KEY *key);
&aesni_generate1("enc") if (!$inline);
&function_begin_B("${PREFIX}_encrypt");
	&mov	("eax",&wparam(0));
	&mov	($key,&wparam(2));
	&movups	($inout0,&QWP(0,"eax"));
	&mov	($rounds,&DWP(240,$key));
	&mov	("eax",&wparam(1));
	if ($inline)
	{   &aesni_inline_generate1("enc");	}
	else
	{   &call	("_aesni_encrypt1");	}
	&movups	(&QWP(0,"eax"),$inout0);
	&ret	();
&function_end_B("${PREFIX}_encrypt");

# void $PREFIX_decrypt (const void *inp,void *out,const AES_KEY *key);
&aesni_generate1("dec") if(!$inline);
&function_begin_B("${PREFIX}_decrypt");
	&mov	("eax",&wparam(0));
	&mov	($key,&wparam(2));
	&movups	($inout0,&QWP(0,"eax"));
	&mov	($rounds,&DWP(240,$key));
	&mov	("eax",&wparam(1));
	if ($inline)
	{   &aesni_inline_generate1("dec");	}
	else
	{   &call	("_aesni_decrypt1");	}
	&movups	(&QWP(0,"eax"),$inout0);
	&ret	();
&function_end_B("${PREFIX}_decrypt");

# _aesni_[en|de]cryptN are private interfaces, N denotes interleave
# factor. Why 3x subroutine were originally used in loops? Even though
# aes[enc|dec] latency was originally 6, it could be scheduled only
# every *2nd* cycle. Thus 3x interleave was the one providing optimal
# utilization, i.e. when subroutine's throughput is virtually same as
# of non-interleaved subroutine [for number of input blocks up to 3].
# This is why it makes no sense to implement 2x subroutine.
# aes[enc|dec] latency in next processor generation is 8, but the
# instructions can be scheduled every cycle. Optimal interleave for
# new processor is therefore 8x, but it's unfeasible to accommodate it
# in XMM registers addreassable in 32-bit mode and therefore 6x is
# used instead...

sub aesni_generate3
{ my $p=shift;

    &function_begin_B("_aesni_${p}rypt3");
	&$movekey	($rndkey0,&QWP(0,$key));
	&shr		($rounds,1);
	&$movekey	($rndkey1,&QWP(16,$key));
	&lea		($key,&DWP(32,$key));
	&xorps		($inout0,$rndkey0);
	&pxor		($inout1,$rndkey0);
	&pxor		($inout2,$rndkey0);
	&$movekey	($rndkey0,&QWP(0,$key));

    &set_label("${p}3_loop");
	eval"&aes${p}	($inout0,$rndkey1)";
	eval"&aes${p}	($inout1,$rndkey1)";
	&dec		($rounds);
	eval"&aes${p}	($inout2,$rndkey1)";
	&$movekey	($rndkey1,&QWP(16,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	eval"&aes${p}	($inout1,$rndkey0)";
	&lea		($key,&DWP(32,$key));
	eval"&aes${p}	($inout2,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0,$key));
	&jnz		(&label("${p}3_loop"));
    eval"&aes${p}	($inout0,$rndkey1)";
    eval"&aes${p}	($inout1,$rndkey1)";
    eval"&aes${p}	($inout2,$rndkey1)";
    eval"&aes${p}last	($inout0,$rndkey0)";
    eval"&aes${p}last	($inout1,$rndkey0)";
    eval"&aes${p}last	($inout2,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt3");
}

# 4x interleave is implemented to improve small block performance,
# most notably [and naturally] 4 block by ~30%. One can argue that one
# should have implemented 5x as well, but improvement  would be <20%,
# so it's not worth it...
sub aesni_generate4
{ my $p=shift;

    &function_begin_B("_aesni_${p}rypt4");
	&$movekey	($rndkey0,&QWP(0,$key));
	&$movekey	($rndkey1,&QWP(16,$key));
	&shr		($rounds,1);
	&lea		($key,&DWP(32,$key));
	&xorps		($inout0,$rndkey0);
	&pxor		($inout1,$rndkey0);
	&pxor		($inout2,$rndkey0);
	&pxor		($inout3,$rndkey0);
	&$movekey	($rndkey0,&QWP(0,$key));

    &set_label("${p}4_loop");
	eval"&aes${p}	($inout0,$rndkey1)";
	eval"&aes${p}	($inout1,$rndkey1)";
	&dec		($rounds);
	eval"&aes${p}	($inout2,$rndkey1)";
	eval"&aes${p}	($inout3,$rndkey1)";
	&$movekey	($rndkey1,&QWP(16,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	eval"&aes${p}	($inout1,$rndkey0)";
	&lea		($key,&DWP(32,$key));
	eval"&aes${p}	($inout2,$rndkey0)";
	eval"&aes${p}	($inout3,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0,$key));
    &jnz		(&label("${p}4_loop"));

    eval"&aes${p}	($inout0,$rndkey1)";
    eval"&aes${p}	($inout1,$rndkey1)";
    eval"&aes${p}	($inout2,$rndkey1)";
    eval"&aes${p}	($inout3,$rndkey1)";
    eval"&aes${p}last	($inout0,$rndkey0)";
    eval"&aes${p}last	($inout1,$rndkey0)";
    eval"&aes${p}last	($inout2,$rndkey0)";
    eval"&aes${p}last	($inout3,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt4");
}

sub aesni_generate6
{ my $p=shift;

    &function_begin_B("_aesni_${p}rypt6");
    &static_label("_aesni_${p}rypt6_enter");
	&$movekey	($rndkey0,&QWP(0,$key));
	&shr		($rounds,1);
	&$movekey	($rndkey1,&QWP(16,$key));
	&lea		($key,&DWP(32,$key));
	&xorps		($inout0,$rndkey0);
	&pxor		($inout1,$rndkey0);	# pxor does better here
	eval"&aes${p}	($inout0,$rndkey1)";
	&pxor		($inout2,$rndkey0);
	eval"&aes${p}	($inout1,$rndkey1)";
	&pxor		($inout3,$rndkey0);
	&dec		($rounds);
	eval"&aes${p}	($inout2,$rndkey1)";
	&pxor		($inout4,$rndkey0);
	eval"&aes${p}	($inout3,$rndkey1)";
	&pxor		($inout5,$rndkey0);
	eval"&aes${p}	($inout4,$rndkey1)";
	&$movekey	($rndkey0,&QWP(0,$key));
	eval"&aes${p}	($inout5,$rndkey1)";
	&jmp		(&label("_aesni_${p}rypt6_enter"));

    &set_label("${p}6_loop",16);
	eval"&aes${p}	($inout0,$rndkey1)";
	eval"&aes${p}	($inout1,$rndkey1)";
	&dec		($rounds);
	eval"&aes${p}	($inout2,$rndkey1)";
	eval"&aes${p}	($inout3,$rndkey1)";
	eval"&aes${p}	($inout4,$rndkey1)";
	eval"&aes${p}	($inout5,$rndkey1)";
    &set_label("_aesni_${p}rypt6_enter",16);
	&$movekey	($rndkey1,&QWP(16,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	eval"&aes${p}	($inout1,$rndkey0)";
	&lea		($key,&DWP(32,$key));
	eval"&aes${p}	($inout2,$rndkey0)";
	eval"&aes${p}	($inout3,$rndkey0)";
	eval"&aes${p}	($inout4,$rndkey0)";
	eval"&aes${p}	($inout5,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0,$key));
    &jnz		(&label("${p}6_loop"));

    eval"&aes${p}	($inout0,$rndkey1)";
    eval"&aes${p}	($inout1,$rndkey1)";
    eval"&aes${p}	($inout2,$rndkey1)";
    eval"&aes${p}	($inout3,$rndkey1)";
    eval"&aes${p}	($inout4,$rndkey1)";
    eval"&aes${p}	($inout5,$rndkey1)";
    eval"&aes${p}last	($inout0,$rndkey0)";
    eval"&aes${p}last	($inout1,$rndkey0)";
    eval"&aes${p}last	($inout2,$rndkey0)";
    eval"&aes${p}last	($inout3,$rndkey0)";
    eval"&aes${p}last	($inout4,$rndkey0)";
    eval"&aes${p}last	($inout5,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt6");
}
&aesni_generate3("enc") if ($PREFIX eq "aesni");
&aesni_generate3("dec");
&aesni_generate4("enc") if ($PREFIX eq "aesni");
&aesni_generate4("dec");
&aesni_generate6("enc") if ($PREFIX eq "aesni");
&aesni_generate6("dec");

if ($PREFIX eq "aesni") {
######################################################################
# void aesni_ecb_encrypt (const void *in, void *out,
#                         size_t length, const AES_KEY *key,
#                         int enc);
&function_begin("aesni_ecb_encrypt");
	&mov	($inp,&wparam(0));
	&mov	($out,&wparam(1));
	&mov	($len,&wparam(2));
	&mov	($key,&wparam(3));
	&mov	($rounds_,&wparam(4));
	&and	($len,-16);
	&jz	(&label("ecb_ret"));
	&mov	($rounds,&DWP(240,$key));
	&test	($rounds_,$rounds_);
	&jz	(&label("ecb_decrypt"));

	&mov	($key_,$key);		# backup $key
	&mov	($rounds_,$rounds);	# backup $rounds
	&cmp	($len,0x60);
	&jb	(&label("ecb_enc_tail"));

	&movdqu	($inout0,&QWP(0,$inp));
	&movdqu	($inout1,&QWP(0x10,$inp));
	&movdqu	($inout2,&QWP(0x20,$inp));
	&movdqu	($inout3,&QWP(0x30,$inp));
	&movdqu	($inout4,&QWP(0x40,$inp));
	&movdqu	($inout5,&QWP(0x50,$inp));
	&lea	($inp,&DWP(0x60,$inp));
	&sub	($len,0x60);
	&jmp	(&label("ecb_enc_loop6_enter"));

&set_label("ecb_enc_loop6",16);
	&movups	(&QWP(0,$out),$inout0);
	&movdqu	($inout0,&QWP(0,$inp));
	&movups	(&QWP(0x10,$out),$inout1);
	&movdqu	($inout1,&QWP(0x10,$inp));
	&movups	(&QWP(0x20,$out),$inout2);
	&movdqu	($inout2,&QWP(0x20,$inp));
	&movups	(&QWP(0x30,$out),$inout3);
	&movdqu	($inout3,&QWP(0x30,$inp));
	&movups	(&QWP(0x40,$out),$inout4);
	&movdqu	($inout4,&QWP(0x40,$inp));
	&movups	(&QWP(0x50,$out),$inout5);
	&lea	($out,&DWP(0x60,$out));
	&movdqu	($inout5,&QWP(0x50,$inp));
	&lea	($inp,&DWP(0x60,$inp));
&set_label("ecb_enc_loop6_enter");

	&call	("_aesni_encrypt6");

	&mov	($key,$key_);		# restore $key
	&mov	($rounds,$rounds_);	# restore $rounds
	&sub	($len,0x60);
	&jnc	(&label("ecb_enc_loop6"));

	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&movups	(&QWP(0x40,$out),$inout4);
	&movups	(&QWP(0x50,$out),$inout5);
	&lea	($out,&DWP(0x60,$out));
	&add	($len,0x60);
	&jz	(&label("ecb_ret"));

&set_label("ecb_enc_tail");
	&movups	($inout0,&QWP(0,$inp));
	&cmp	($len,0x20);
	&jb	(&label("ecb_enc_one"));
	&movups	($inout1,&QWP(0x10,$inp));
	&je	(&label("ecb_enc_two"));
	&movups	($inout2,&QWP(0x20,$inp));
	&cmp	($len,0x40);
	&jb	(&label("ecb_enc_three"));
	&movups	($inout3,&QWP(0x30,$inp));
	&je	(&label("ecb_enc_four"));
	&movups	($inout4,&QWP(0x40,$inp));
	&xorps	($inout5,$inout5);
	&call	("_aesni_encrypt6");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&movups	(&QWP(0x40,$out),$inout4);
	jmp	(&label("ecb_ret"));

&set_label("ecb_enc_one",16);
	if ($inline)
	{   &aesni_inline_generate1("enc");	}
	else
	{   &call	("_aesni_encrypt1");	}
	&movups	(&QWP(0,$out),$inout0);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_enc_two",16);
	&xorps	($inout2,$inout2);
	&call	("_aesni_encrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_enc_three",16);
	&call	("_aesni_encrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_enc_four",16);
	&call	("_aesni_encrypt4");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&jmp	(&label("ecb_ret"));
######################################################################
&set_label("ecb_decrypt",16);
	&mov	($key_,$key);		# backup $key
	&mov	($rounds_,$rounds);	# backup $rounds
	&cmp	($len,0x60);
	&jb	(&label("ecb_dec_tail"));

	&movdqu	($inout0,&QWP(0,$inp));
	&movdqu	($inout1,&QWP(0x10,$inp));
	&movdqu	($inout2,&QWP(0x20,$inp));
	&movdqu	($inout3,&QWP(0x30,$inp));
	&movdqu	($inout4,&QWP(0x40,$inp));
	&movdqu	($inout5,&QWP(0x50,$inp));
	&lea	($inp,&DWP(0x60,$inp));
	&sub	($len,0x60);
	&jmp	(&label("ecb_dec_loop6_enter"));

&set_label("ecb_dec_loop6",16);
	&movups	(&QWP(0,$out),$inout0);
	&movdqu	($inout0,&QWP(0,$inp));
	&movups	(&QWP(0x10,$out),$inout1);
	&movdqu	($inout1,&QWP(0x10,$inp));
	&movups	(&QWP(0x20,$out),$inout2);
	&movdqu	($inout2,&QWP(0x20,$inp));
	&movups	(&QWP(0x30,$out),$inout3);
	&movdqu	($inout3,&QWP(0x30,$inp));
	&movups	(&QWP(0x40,$out),$inout4);
	&movdqu	($inout4,&QWP(0x40,$inp));
	&movups	(&QWP(0x50,$out),$inout5);
	&lea	($out,&DWP(0x60,$out));
	&movdqu	($inout5,&QWP(0x50,$inp));
	&lea	($inp,&DWP(0x60,$inp));
&set_label("ecb_dec_loop6_enter");

	&call	("_aesni_decrypt6");

	&mov	($key,$key_);		# restore $key
	&mov	($rounds,$rounds_);	# restore $rounds
	&sub	($len,0x60);
	&jnc	(&label("ecb_dec_loop6"));

	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&movups	(&QWP(0x40,$out),$inout4);
	&movups	(&QWP(0x50,$out),$inout5);
	&lea	($out,&DWP(0x60,$out));
	&add	($len,0x60);
	&jz	(&label("ecb_ret"));

&set_label("ecb_dec_tail");
	&movups	($inout0,&QWP(0,$inp));
	&cmp	($len,0x20);
	&jb	(&label("ecb_dec_one"));
	&movups	($inout1,&QWP(0x10,$inp));
	&je	(&label("ecb_dec_two"));
	&movups	($inout2,&QWP(0x20,$inp));
	&cmp	($len,0x40);
	&jb	(&label("ecb_dec_three"));
	&movups	($inout3,&QWP(0x30,$inp));
	&je	(&label("ecb_dec_four"));
	&movups	($inout4,&QWP(0x40,$inp));
	&xorps	($inout5,$inout5);
	&call	("_aesni_decrypt6");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&movups	(&QWP(0x40,$out),$inout4);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_one",16);
	if ($inline)
	{   &aesni_inline_generate1("dec");	}
	else
	{   &call	("_aesni_decrypt1");	}
	&movups	(&QWP(0,$out),$inout0);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_two",16);
	&xorps	($inout2,$inout2);
	&call	("_aesni_decrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_three",16);
	&call	("_aesni_decrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_four",16);
	&call	("_aesni_decrypt4");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);

&set_label("ecb_ret");
&function_end("aesni_ecb_encrypt");
}

######################################################################
# void $PREFIX_cbc_encrypt (const void *inp, void *out,
#                           size_t length, const AES_KEY *key,
#                           unsigned char *ivp,const int enc);
&function_begin("${PREFIX}_cbc_encrypt");
	&mov	($inp,&wparam(0));
	&mov	($rounds_,"esp");
	&mov	($out,&wparam(1));
	&sub	($rounds_,24);
	&mov	($len,&wparam(2));
	&and	($rounds_,-16);
	&mov	($key,&wparam(3));
	&mov	($key_,&wparam(4));
	&test	($len,$len);
	&jz	(&label("cbc_abort"));

	&cmp	(&wparam(5),0);
	&xchg	($rounds_,"esp");		# alloca
	&movups	($ivec,&QWP(0,$key_));		# load IV
	&mov	($rounds,&DWP(240,$key));
	&mov	($key_,$key);			# backup $key
	&mov	(&DWP(16,"esp"),$rounds_);	# save original %esp
	&mov	($rounds_,$rounds);		# backup $rounds
	&je	(&label("cbc_decrypt"));

	&movaps	($inout0,$ivec);
	&cmp	($len,16);
	&jb	(&label("cbc_enc_tail"));
	&sub	($len,16);
	&jmp	(&label("cbc_enc_loop"));

&set_label("cbc_enc_loop",16);
	&movups	($ivec,&QWP(0,$inp));		# input actually
	&lea	($inp,&DWP(16,$inp));
	if ($inline)
	{   &aesni_inline_generate1("enc",$inout0,$ivec);	}
	else
	{   &xorps($inout0,$ivec); &call("_aesni_encrypt1");	}
	&mov	($rounds,$rounds_);	# restore $rounds
	&mov	($key,$key_);		# restore $key
	&movups	(&QWP(0,$out),$inout0);	# store output
	&lea	($out,&DWP(16,$out));
	&sub	($len,16);
	&jnc	(&label("cbc_enc_loop"));
	&add	($len,16);
	&jnz	(&label("cbc_enc_tail"));
	&movaps	($ivec,$inout0);
	&jmp	(&label("cbc_ret"));

&set_label("cbc_enc_tail");
	&mov	("ecx",$len);		# zaps $rounds
	&data_word(0xA4F3F689);		# rep movsb
	&mov	("ecx",16);		# zero tail
	&sub	("ecx",$len);
	&xor	("eax","eax");		# zaps $len
	&data_word(0xAAF3F689);		# rep stosb
	&lea	($out,&DWP(-16,$out));	# rewind $out by 1 block
	&mov	($rounds,$rounds_);	# restore $rounds
	&mov	($inp,$out);		# $inp and $out are the same
	&mov	($key,$key_);		# restore $key
	&jmp	(&label("cbc_enc_loop"));
######################################################################
&set_label("cbc_decrypt",16);
	&cmp	($len,0x50);
	&jbe	(&label("cbc_dec_tail"));
	&movaps	(&QWP(0,"esp"),$ivec);		# save IV
	&sub	($len,0x50);
	&jmp	(&label("cbc_dec_loop6_enter"));

&set_label("cbc_dec_loop6",16);
	&movaps	(&QWP(0,"esp"),$rndkey0);	# save IV
	&movups	(&QWP(0,$out),$inout5);
	&lea	($out,&DWP(0x10,$out));
&set_label("cbc_dec_loop6_enter");
	&movdqu	($inout0,&QWP(0,$inp));
	&movdqu	($inout1,&QWP(0x10,$inp));
	&movdqu	($inout2,&QWP(0x20,$inp));
	&movdqu	($inout3,&QWP(0x30,$inp));
	&movdqu	($inout4,&QWP(0x40,$inp));
	&movdqu	($inout5,&QWP(0x50,$inp));

	&call	("_aesni_decrypt6");

	&movups	($rndkey1,&QWP(0,$inp));
	&movups	($rndkey0,&QWP(0x10,$inp));
	&xorps	($inout0,&QWP(0,"esp"));	# ^=IV
	&xorps	($inout1,$rndkey1);
	&movups	($rndkey1,&QWP(0x20,$inp));
	&xorps	($inout2,$rndkey0);
	&movups	($rndkey0,&QWP(0x30,$inp));
	&xorps	($inout3,$rndkey1);
	&movups	($rndkey1,&QWP(0x40,$inp));
	&xorps	($inout4,$rndkey0);
	&movups	($rndkey0,&QWP(0x50,$inp));	# IV
	&xorps	($inout5,$rndkey1);
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&lea	($inp,&DWP(0x60,$inp));
	&movups	(&QWP(0x20,$out),$inout2);
	&mov	($rounds,$rounds_)		# restore $rounds
	&movups	(&QWP(0x30,$out),$inout3);
	&mov	($key,$key_);			# restore $key
	&movups	(&QWP(0x40,$out),$inout4);
	&lea	($out,&DWP(0x50,$out));
	&sub	($len,0x60);
	&ja	(&label("cbc_dec_loop6"));

	&movaps	($inout0,$inout5);
	&movaps	($ivec,$rndkey0);
	&add	($len,0x50);
	&jle	(&label("cbc_dec_tail_collected"));
	&movups	(&QWP(0,$out),$inout0);
	&lea	($out,&DWP(0x10,$out));
&set_label("cbc_dec_tail");
	&movups	($inout0,&QWP(0,$inp));
	&movaps	($in0,$inout0);
	&cmp	($len,0x10);
	&jbe	(&label("cbc_dec_one"));

	&movups	($inout1,&QWP(0x10,$inp));
	&movaps	($in1,$inout1);
	&cmp	($len,0x20);
	&jbe	(&label("cbc_dec_two"));

	&movups	($inout2,&QWP(0x20,$inp));
	&cmp	($len,0x30);
	&jbe	(&label("cbc_dec_three"));

	&movups	($inout3,&QWP(0x30,$inp));
	&cmp	($len,0x40);
	&jbe	(&label("cbc_dec_four"));

	&movups	($inout4,&QWP(0x40,$inp));
	&movaps	(&QWP(0,"esp"),$ivec);		# save IV
	&movups	($inout0,&QWP(0,$inp));
	&xorps	($inout5,$inout5);
	&call	("_aesni_decrypt6");
	&movups	($rndkey1,&QWP(0,$inp));
	&movups	($rndkey0,&QWP(0x10,$inp));
	&xorps	($inout0,&QWP(0,"esp"));	# ^= IV
	&xorps	($inout1,$rndkey1);
	&movups	($rndkey1,&QWP(0x20,$inp));
	&xorps	($inout2,$rndkey0);
	&movups	($rndkey0,&QWP(0x30,$inp));
	&xorps	($inout3,$rndkey1);
	&movups	($ivec,&QWP(0x40,$inp));	# IV
	&xorps	($inout4,$rndkey0);
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&lea	($out,&DWP(0x40,$out));
	&movaps	($inout0,$inout4);
	&sub	($len,0x50);
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_one",16);
	if ($inline)
	{   &aesni_inline_generate1("dec");	}
	else
	{   &call	("_aesni_decrypt1");	}
	&xorps	($inout0,$ivec);
	&movaps	($ivec,$in0);
	&sub	($len,0x10);
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_two",16);
	&xorps	($inout2,$inout2);
	&call	("_aesni_decrypt3");
	&xorps	($inout0,$ivec);
	&xorps	($inout1,$in0);
	&movups	(&QWP(0,$out),$inout0);
	&movaps	($inout0,$inout1);
	&lea	($out,&DWP(0x10,$out));
	&movaps	($ivec,$in1);
	&sub	($len,0x20);
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_three",16);
	&call	("_aesni_decrypt3");
	&xorps	($inout0,$ivec);
	&xorps	($inout1,$in0);
	&xorps	($inout2,$in1);
	&movups	(&QWP(0,$out),$inout0);
	&movaps	($inout0,$inout2);
	&movups	(&QWP(0x10,$out),$inout1);
	&lea	($out,&DWP(0x20,$out));
	&movups	($ivec,&QWP(0x20,$inp));
	&sub	($len,0x30);
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_four",16);
	&call	("_aesni_decrypt4");
	&movups	($rndkey1,&QWP(0x10,$inp));
	&movups	($rndkey0,&QWP(0x20,$inp));
	&xorps	($inout0,$ivec);
	&movups	($ivec,&QWP(0x30,$inp));
	&xorps	($inout1,$in0);
	&movups	(&QWP(0,$out),$inout0);
	&xorps	($inout2,$rndkey1);
	&movups	(&QWP(0x10,$out),$inout1);
	&xorps	($inout3,$rndkey0);
	&movups	(&QWP(0x20,$out),$inout2);
	&lea	($out,&DWP(0x30,$out));
	&movaps	($inout0,$inout3);
	&sub	($len,0x40);

&set_label("cbc_dec_tail_collected");
	&and	($len,15);
	&jnz	(&label("cbc_dec_tail_partial"));
	&movups	(&QWP(0,$out),$inout0);
	&jmp	(&label("cbc_ret"));

&set_label("cbc_dec_tail_partial",16);
	&movaps	(&QWP(0,"esp"),$inout0);
	&mov	("ecx",16);
	&mov	($inp,"esp");
	&sub	("ecx",$len);
	&data_word(0xA4F3F689);		# rep movsb

&set_label("cbc_ret");
	&mov	("esp",&DWP(16,"esp"));	# pull original %esp
	&mov	($key_,&wparam(4));
	&movups	(&QWP(0,$key_),$ivec);	# output IV
&set_label("cbc_abort");
&function_end("${PREFIX}_cbc_encrypt");

######################################################################
# Mechanical port from aesni-x86_64.pl.
#
# _aesni_set_encrypt_key is private interface,
# input:
#	"eax"	const unsigned char *userKey
#	$rounds	int bits
#	$key	AES_KEY *key
# output:
#	"eax"	return code
#	$round	rounds

&function_begin_B("_aesni_set_encrypt_key");
	&test	("eax","eax");
	&jz	(&label("bad_pointer"));
	&test	($key,$key);
	&jz	(&label("bad_pointer"));

	&movups	("xmm0",&QWP(0,"eax"));	# pull first 128 bits of *userKey
	&xorps	("xmm4","xmm4");	# low dword of xmm4 is assumed 0
	&lea	($key,&DWP(16,$key));
	&cmp	($rounds,256);
	&je	(&label("14rounds"));
	&cmp	($rounds,192);
	&je	(&label("12rounds"));
	&cmp	($rounds,128);
	&jne	(&label("bad_keybits"));

&set_label("10rounds",16);
	&mov		($rounds,9);
	&$movekey	(&QWP(-16,$key),"xmm0");	# round 0
	&aeskeygenassist("xmm1","xmm0",0x01);		# round 1
	&call		(&label("key_128_cold"));
	&aeskeygenassist("xmm1","xmm0",0x2);		# round 2
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x04);		# round 3
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x08);		# round 4
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x10);		# round 5
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x20);		# round 6
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x40);		# round 7
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x80);		# round 8
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x1b);		# round 9
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x36);		# round 10
	&call		(&label("key_128"));
	&$movekey	(&QWP(0,$key),"xmm0");
	&mov		(&DWP(80,$key),$rounds);
	&xor		("eax","eax");
	&ret();

&set_label("key_128",16);
	&$movekey	(&QWP(0,$key),"xmm0");
	&lea		($key,&DWP(16,$key));
&set_label("key_128_cold");
	&shufps		("xmm4","xmm0",0b00010000);
	&xorps		("xmm0","xmm4");
	&shufps		("xmm4","xmm0",0b10001100);
	&xorps		("xmm0","xmm4");
	&shufps		("xmm1","xmm1",0b11111111);	# critical path
	&xorps		("xmm0","xmm1");
	&ret();

&set_label("12rounds",16);
	&movq		("xmm2",&QWP(16,"eax"));	# remaining 1/3 of *userKey
	&mov		($rounds,11);
	&$movekey	(&QWP(-16,$key),"xmm0")		# round 0
	&aeskeygenassist("xmm1","xmm2",0x01);		# round 1,2
	&call		(&label("key_192a_cold"));
	&aeskeygenassist("xmm1","xmm2",0x02);		# round 2,3
	&call		(&label("key_192b"));
	&aeskeygenassist("xmm1","xmm2",0x04);		# round 4,5
	&call		(&label("key_192a"));
	&aeskeygenassist("xmm1","xmm2",0x08);		# round 5,6
	&call		(&label("key_192b"));
	&aeskeygenassist("xmm1","xmm2",0x10);		# round 7,8
	&call		(&label("key_192a"));
	&aeskeygenassist("xmm1","xmm2",0x20);		# round 8,9
	&call		(&label("key_192b"));
	&aeskeygenassist("xmm1","xmm2",0x40);		# round 10,11
	&call		(&label("key_192a"));
	&aeskeygenassist("xmm1","xmm2",0x80);		# round 11,12
	&call		(&label("key_192b"));
	&$movekey	(&QWP(0,$key),"xmm0");
	&mov		(&DWP(48,$key),$rounds);
	&xor		("eax","eax");
	&ret();

&set_label("key_192a",16);
	&$movekey	(&QWP(0,$key),"xmm0");
	&lea		($key,&DWP(16,$key));
&set_label("key_192a_cold",16);
	&movaps		("xmm5","xmm2");
&set_label("key_192b_warm");
	&shufps		("xmm4","xmm0",0b00010000);
	&movdqa		("xmm3","xmm2");
	&xorps		("xmm0","xmm4");
	&shufps		("xmm4","xmm0",0b10001100);
	&pslldq		("xmm3",4);
	&xorps		("xmm0","xmm4");
	&pshufd		("xmm1","xmm1",0b01010101);	# critical path
	&pxor		("xmm2","xmm3");
	&pxor		("xmm0","xmm1");
	&pshufd		("xmm3","xmm0",0b11111111);
	&pxor		("xmm2","xmm3");
	&ret();

&set_label("key_192b",16);
	&movaps		("xmm3","xmm0");
	&shufps		("xmm5","xmm0",0b01000100);
	&$movekey	(&QWP(0,$key),"xmm5");
	&shufps		("xmm3","xmm2",0b01001110);
	&$movekey	(&QWP(16,$key),"xmm3");
	&lea		($key,&DWP(32,$key));
	&jmp		(&label("key_192b_warm"));

&set_label("14rounds",16);
	&movups		("xmm2",&QWP(16,"eax"));	# remaining half of *userKey
	&mov		($rounds,13);
	&lea		($key,&DWP(16,$key));
	&$movekey	(&QWP(-32,$key),"xmm0");	# round 0
	&$movekey	(&QWP(-16,$key),"xmm2");	# round 1
	&aeskeygenassist("xmm1","xmm2",0x01);		# round 2
	&call		(&label("key_256a_cold"));
	&aeskeygenassist("xmm1","xmm0",0x01);		# round 3
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x02);		# round 4
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x02);		# round 5
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x04);		# round 6
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x04);		# round 7
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x08);		# round 8
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x08);		# round 9
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x10);		# round 10
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x10);		# round 11
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x20);		# round 12
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x20);		# round 13
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x40);		# round 14
	&call		(&label("key_256a"));
	&$movekey	(&QWP(0,$key),"xmm0");
	&mov		(&DWP(16,$key),$rounds);
	&xor		("eax","eax");
	&ret();

&set_label("key_256a",16);
	&$movekey	(&QWP(0,$key),"xmm2");
	&lea		($key,&DWP(16,$key));
&set_label("key_256a_cold");
	&shufps		("xmm4","xmm0",0b00010000);
	&xorps		("xmm0","xmm4");
	&shufps		("xmm4","xmm0",0b10001100);
	&xorps		("xmm0","xmm4");
	&shufps		("xmm1","xmm1",0b11111111);	# critical path
	&xorps		("xmm0","xmm1");
	&ret();

&set_label("key_256b",16);
	&$movekey	(&QWP(0,$key),"xmm0");
	&lea		($key,&DWP(16,$key));

	&shufps		("xmm4","xmm2",0b00010000);
	&xorps		("xmm2","xmm4");
	&shufps		("xmm4","xmm2",0b10001100);
	&xorps		("xmm2","xmm4");
	&shufps		("xmm1","xmm1",0b10101010);	# critical path
	&xorps		("xmm2","xmm1");
	&ret();

&set_label("bad_pointer",4);
	&mov	("eax",-1);
	&ret	();
&set_label("bad_keybits",4);
	&mov	("eax",-2);
	&ret	();
&function_end_B("_aesni_set_encrypt_key");

# int $PREFIX_set_encrypt_key (const unsigned char *userKey, int bits,
#                              AES_KEY *key)
&function_begin_B("${PREFIX}_set_encrypt_key");
	&mov	("eax",&wparam(0));
	&mov	($rounds,&wparam(1));
	&mov	($key,&wparam(2));
	&call	("_aesni_set_encrypt_key");
	&ret	();
&function_end_B("${PREFIX}_set_encrypt_key");

# int $PREFIX_set_decrypt_key (const unsigned char *userKey, int bits,
#                              AES_KEY *key)
&function_begin_B("${PREFIX}_set_decrypt_key");
	&mov	("eax",&wparam(0));
	&mov	($rounds,&wparam(1));
	&mov	($key,&wparam(2));
	&call	("_aesni_set_encrypt_key");
	&mov	($key,&wparam(2));
	&shl	($rounds,4)	# rounds-1 after _aesni_set_encrypt_key
	&test	("eax","eax");
	&jnz	(&label("dec_key_ret"));
	&lea	("eax",&DWP(16,$key,$rounds));	# end of key schedule

	&$movekey	("xmm0",&QWP(0,$key));	# just swap
	&$movekey	("xmm1",&QWP(0,"eax"));
	&$movekey	(&QWP(0,"eax"),"xmm0");
	&$movekey	(&QWP(0,$key),"xmm1");
	&lea		($key,&DWP(16,$key));
	&lea		("eax",&DWP(-16,"eax"));

&set_label("dec_key_inverse");
	&$movekey	("xmm0",&QWP(0,$key));	# swap and inverse
	&$movekey	("xmm1",&QWP(0,"eax"));
	&aesimc		("xmm0","xmm0");
	&aesimc		("xmm1","xmm1");
	&lea		($key,&DWP(16,$key));
	&lea		("eax",&DWP(-16,"eax"));
	&$movekey	(&QWP(16,"eax"),"xmm0");
	&$movekey	(&QWP(-16,$key),"xmm1");
	&cmp		("eax",$key);
	&ja		(&label("dec_key_inverse"));

	&$movekey	("xmm0",&QWP(0,$key));	# inverse middle
	&aesimc		("xmm0","xmm0");
	&$movekey	(&QWP(0,$key),"xmm0");

	&xor		("eax","eax");		# return success
&set_label("dec_key_ret");
	&ret	();
&function_end_B("${PREFIX}_set_decrypt_key");
&asciz("AES for Intel AES-NI, CRYPTOGAMS by <appro\@openssl.org>");

&asm_finish();
