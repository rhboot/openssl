#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# This module implements support for Intel AES-NI extension. In
# OpenSSL context it's used with Intel engine, but can also be used as
# drop-in replacement for crypto/aes/asm/aes-x86_64.pl [see below for
# details].
#
# Performance.
#
# Given aes(enc|dec) instructions' latency asymptotic performance for
# non-parallelizable modes such as CBC encrypt is 3.75 cycles per byte
# processed with 128-bit key. And given their throughput asymptotic
# performance for parallelizable modes is 1.25 cycles per byte. Being
# asymptotic limit it's not something you commonly achieve in reality,
# but how close does one get? Below are results collected for
# different modes and block sized. Pairs of numbers are for en-/
# decryption.
#
#	16-byte     64-byte     256-byte    1-KB        8-KB
# ECB	4.25/4.25   1.38/1.38   1.28/1.28   1.26/1.26	1.26/1.26
# CTR	5.42/5.42   1.92/1.92   1.44/1.44   1.28/1.28   1.26/1.26
# CBC	4.38/4.43   4.15/1.43   4.07/1.32   4.07/1.29   4.06/1.28
# CCM	5.66/9.42   4.42/5.41   4.16/4.40   4.09/4.15   4.06/4.07   
# OFB	5.42/5.42   4.64/4.64   4.44/4.44   4.39/4.39   4.38/4.38
# CFB	5.73/5.85   5.56/5.62   5.48/5.56   5.47/5.55   5.47/5.55
#
# ECB, CTR, CBC and CCM results are free from EVP overhead. This means
# that otherwise used 'openssl speed -evp aes-128-??? -engine aesni
# [-decrypt]' will exhibit 10-15% worse results for smaller blocks.
# The results were collected with specially crafted speed.c benchmark
# in order to compare them with results reported in "Intel Advanced
# Encryption Standard (AES) New Instruction Set" White Paper Revision
# 3.0 dated May 2010. All above results are consistently better. This
# module also provides better performance for block sizes smaller than
# 128 bytes in points *not* represented in the above table.
#
# Looking at the results for 8-KB buffer.
#
# CFB and OFB results are far from the limit, because implementation
# uses "generic" CRYPTO_[c|o]fb128_encrypt interfaces relying on
# single-block aesni_encrypt, which is not the most optimal way to go.
# CBC encrypt result is unexpectedly high and there is no documented
# explanation for it. Seemingly there is a small penalty for feeding
# the result back to AES unit the way it's done in CBC mode. There is
# nothing one can do and the result appears optimal. CCM result is
# identical to CBC, because CBC-MAC is essentially CBC encrypt without
# saving output. CCM CTR "stays invisible," because it's neatly
# interleaved wih CBC-MAC. This provides ~30% improvement over
# "straghtforward" CCM implementation with CTR and CBC-MAC performed
# disjointly. Parallelizable modes practically achieve the theoretical
# limit.
#
# Looking at how results vary with buffer size.
#
# Curves are practically saturated at 1-KB buffer size. In most cases
# "256-byte" performance is >95%, and "64-byte" is ~90% of "8-KB" one.
# CTR curve doesn't follow this pattern and is "slowest" changing one
# with "256-byte" result being 87% of "8-KB." This is because overhead
# in CTR mode is most computationally intensive. Small-block CCM
# decrypt is slower than encrypt, because first CTR and last CBC-MAC
# iterations can't be interleaved.
#
# Results for 192- and 256-bit keys.
#
# EVP-free results were observed to scale perfectly with number of
# rounds for larger block sizes, i.e. 192-bit result being 10/12 times
# lower and 256-bit one - 10/14. Well, in CBC encrypt case differences
# are a tad smaller, because the above mentioned penalty biases all
# results by same constant value. In similar way function call
# overhead affects small-block performance, as well as OFB and CFB
# results. Differences are not large, most common coefficients are
# 10/11.7 and 10/13.4 (as opposite to 10/12.0 and 10/14.0), but one
# observe even 10/11.2 and 10/12.4 (CTR, OFB, CFB)...

# January 2011
#
# While Westmere processor features 6 cycles latency for aes[enc|dec]
# instructions, which can be scheduled every second cycle, Sandy
# Bridge spends 8 cycles per instruction, but it can schedule them
# every cycle. This means that code targeting Westmere would perform
# suboptimally on Sandy Bridge. Therefore this update.
#
# In addition, non-parallelizable CBC encrypt (as well as CCM) is
# optimized. Relative improvement might appear modest, 8% on Westmere,
# but in absolute terms it's 3.77 cycles per byte encrypted with
# 128-bit key on Westmere, and 5.07 - on Sandy Bridge. These numbers
# should be compared to asymptotic limits of 3.75 for Westmere and
# 5.00 for Sandy Bridge. Actually, the fact that they get this close
# to asymptotic limits is quite amazing. Indeed, the limit is
# calculated as latency times number of rounds, 10 for 128-bit key,
# and divided by 16, the number of bytes in block, or in other words
# it accounts *solely* for aesenc instructions. But there are extra
# instructions, and numbers so close to the asymptotic limits mean
# that it's as if it takes as little as *one* additional cycle to
# execute all of them. How is it possible? It is possible thanks to
# out-of-order execution logic, which manages to overlap post-
# processing of previous block, things like saving the output, with
# actual encryption of current block, as well as pre-processing of
# current block, things like fetching input and xor-ing it with
# 0-round element of the key schedule, with actual encryption of
# previous block. Keep this in mind...
#
# For parallelizable modes, such as ECB, CBC decrypt, CTR, higher
# performance is achieved by interleaving instructions working on
# independent blocks. In which case asymptotic limit for such modes
# can be obtained by dividing above mentioned numbers by AES
# instructions' interleave factor. Westmere can execute at most 3 
# instructions at a time, meaning that optimal interleave factor is 3,
# and that's where the "magic" number of 1.25 come from. "Optimal
# interleave factor" means that increase of interleave factor does
# not improve performance. The formula has proven to reflect reality
# pretty well on Westmere... Sandy Bridge on the other hand can
# execute up to 8 AES instructions at a time, so how does varying
# interleave factor affect the performance? Here is table for ECB
# (numbers are cycles per byte processed with 128-bit key):
#
# instruction interleave factor		3x	6x	8x
# theoretical asymptotic limit		1.67	0.83	0.625
# measured performance for 8KB block	1.05	0.86	0.84
#
# "as if" interleave factor		4.7x	5.8x	6.0x
#
# Further data for other parallelizable modes:
#
# CBC decrypt				1.16	0.93	0.93
# CTR					1.14	0.91	n/a
#
# Well, given 3x column it's probably inappropriate to call the limit
# asymptotic, if it can be surpassed, isn't it? What happens there?
# Rewind to CBC paragraph for the answer. Yes, out-of-order execution
# magic is responsible for this. Processor overlaps not only the
# additional instructions with AES ones, but even AES instuctions
# processing adjacent triplets of independent blocks. In the 6x case
# additional instructions  still claim disproportionally small amount
# of additional cycles, but in 8x case number of instructions must be
# a tad too high for out-of-order logic to cope with, and AES unit
# remains underutilized... As you can see 8x interleave is hardly
# justifiable, so there no need to feel bad that 32-bit aesni-x86.pl
# utilizies 6x interleave because of limited register bank capacity.
#
# Higher interleave factors do have negative impact on Westmere
# performance. While for ECB mode it's negligible ~1.5%, other
# parallelizables perform ~5% worse, which is outweighed by ~25%
# improvement on Sandy Bridge. To balance regression on Westmere
# CTR mode was implemented with 6x aesenc interleave factor.

$PREFIX="aesni";	# if $PREFIX is set to "AES", the script
			# generates drop-in replacement for
			# crypto/aes/asm/aes-x86_64.pl:-)

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

$movkey = $PREFIX eq "aesni" ? "movups" : "movups";
@_4args=$win64?	("%rcx","%rdx","%r8", "%r9") :	# Win64 order
		("%rdi","%rsi","%rdx","%rcx");	# Unix order

$code=".text\n";

$rounds="%eax";	# input to and changed by aesni_[en|de]cryptN !!!
# this is natural Unix argument order for public $PREFIX_[ecb|cbc]_encrypt ...
$inp="%rdi";
$out="%rsi";
$len="%rdx";
$key="%rcx";	# input to and changed by aesni_[en|de]cryptN !!!
$ivp="%r8";	# cbc, ctr, ...

$rnds_="%r10d";	# backup copy for $rounds
$key_="%r11";	# backup copy for $key

# %xmm register layout
$rndkey0="%xmm0";	$rndkey1="%xmm1";
$inout0="%xmm2";	$inout1="%xmm3";
$inout2="%xmm4";	$inout3="%xmm5";
$inout4="%xmm6";	$inout5="%xmm7";
$inout6="%xmm8";	$inout7="%xmm9";

$in2="%xmm6";		$in1="%xmm7";	# used in CBC decrypt, CTR, ...
$in0="%xmm8";		$iv="%xmm9";

# Inline version of internal aesni_[en|de]crypt1.
#
# Why folded loop? Because aes[enc|dec] is slow enough to accommodate
# cycles which take care of loop variables...
{ my $sn;
sub aesni_generate1 {
my ($p,$key,$rounds,$inout,$ivec)=@_;	$inout=$inout0 if (!defined($inout));
++$sn;
$code.=<<___;
	$movkey	($key),$rndkey0
	$movkey	16($key),$rndkey1
___
$code.=<<___ if (defined($ivec));
	xorps	$rndkey0,$ivec
	lea	32($key),$key
	xorps	$ivec,$inout
___
$code.=<<___ if (!defined($ivec));
	lea	32($key),$key
	xorps	$rndkey0,$inout
___
$code.=<<___;
.Loop_${p}1_$sn:
	aes${p}	$rndkey1,$inout
	dec	$rounds
	$movkey	($key),$rndkey1
	lea	16($key),$key
	jnz	.Loop_${p}1_$sn	# loop body is 16 bytes
	aes${p}last	$rndkey1,$inout
___
}}
# void $PREFIX_[en|de]crypt (const void *inp,void *out,const AES_KEY *key);
#
{ my ($inp,$out,$key) = @_4args;

$code.=<<___;
.globl	${PREFIX}_encrypt
.type	${PREFIX}_encrypt,\@abi-omnipotent
.align	16
${PREFIX}_encrypt:
	movups	($inp),$inout0		# load input
	mov	240($key),$rounds	# key->rounds
___
	&aesni_generate1("enc",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)		# output
	ret
.size	${PREFIX}_encrypt,.-${PREFIX}_encrypt

.globl	${PREFIX}_decrypt
.type	${PREFIX}_decrypt,\@abi-omnipotent
.align	16
${PREFIX}_decrypt:
	movups	($inp),$inout0		# load input
	mov	240($key),$rounds	# key->rounds
___
	&aesni_generate1("dec",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)		# output
	ret
.size	${PREFIX}_decrypt, .-${PREFIX}_decrypt
___
}

# _aesni_[en|de]cryptN are private interfaces, N denotes interleave
# factor. Why 3x subroutine were originally used in loops? Even though
# aes[enc|dec] latency was originally 6, it could be scheduled only
# every *2nd* cycle. Thus 3x interleave was the one providing optimal
# utilization, i.e. when subroutine's throughput is virtually same as
# of non-interleaved subroutine [for number of input blocks up to 3].
# This is why it makes no sense to implement 2x subroutine.
# aes[enc|dec] latency in next processor generation is 8, but the
# instructions can be scheduled every cycle. Optimal interleave for
# new processor is therefore 8x...
sub aesni_generate3 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-2] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt3,\@abi-omnipotent
.align	16
_aesni_${dir}rypt3:
	$movkey	($key),$rndkey0
	shr	\$1,$rounds
	$movkey	16($key),$rndkey1
	lea	32($key),$key
	xorps	$rndkey0,$inout0
	xorps	$rndkey0,$inout1
	xorps	$rndkey0,$inout2
	$movkey		($key),$rndkey0

.L${dir}_loop3:
	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	$movkey		16($key),$rndkey1
	aes${dir}	$rndkey0,$inout0
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	$movkey		($key),$rndkey0
	jnz		.L${dir}_loop3

	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	ret
.size	_aesni_${dir}rypt3,.-_aesni_${dir}rypt3
___
}
# 4x interleave is implemented to improve small block performance,
# most notably [and naturally] 4 block by ~30%. One can argue that one
# should have implemented 5x as well, but improvement would be <20%,
# so it's not worth it...
sub aesni_generate4 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-3] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt4,\@abi-omnipotent
.align	16
_aesni_${dir}rypt4:
	$movkey	($key),$rndkey0
	shr	\$1,$rounds
	$movkey	16($key),$rndkey1
	lea	32($key),$key
	xorps	$rndkey0,$inout0
	xorps	$rndkey0,$inout1
	xorps	$rndkey0,$inout2
	xorps	$rndkey0,$inout3
	$movkey	($key),$rndkey0

.L${dir}_loop4:
	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	$movkey		16($key),$rndkey1
	aes${dir}	$rndkey0,$inout0
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	aes${dir}	$rndkey0,$inout3
	$movkey		($key),$rndkey0
	jnz		.L${dir}_loop4

	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	aes${dir}last	$rndkey0,$inout3
	ret
.size	_aesni_${dir}rypt4,.-_aesni_${dir}rypt4
___
}
sub aesni_generate6 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-5] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt6,\@abi-omnipotent
.align	16
_aesni_${dir}rypt6:
	$movkey		($key),$rndkey0
	shr		\$1,$rounds
	$movkey		16($key),$rndkey1
	lea		32($key),$key
	xorps		$rndkey0,$inout0
	pxor		$rndkey0,$inout1
	aes${dir}	$rndkey1,$inout0
	pxor		$rndkey0,$inout2
	aes${dir}	$rndkey1,$inout1
	pxor		$rndkey0,$inout3
	aes${dir}	$rndkey1,$inout2
	pxor		$rndkey0,$inout4
	aes${dir}	$rndkey1,$inout3
	pxor		$rndkey0,$inout5
	dec		$rounds
	aes${dir}	$rndkey1,$inout4
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout5
	jmp		.L${dir}_loop6_enter
.align	16
.L${dir}_loop6:
	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey1,$inout4
	aes${dir}	$rndkey1,$inout5
.L${dir}_loop6_enter:				# happens to be 16-byte aligned
	$movkey		16($key),$rndkey1
	aes${dir}	$rndkey0,$inout0
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	aes${dir}	$rndkey0,$inout3
	aes${dir}	$rndkey0,$inout4
	aes${dir}	$rndkey0,$inout5
	$movkey		($key),$rndkey0
	jnz		.L${dir}_loop6

	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey1,$inout4
	aes${dir}	$rndkey1,$inout5
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	aes${dir}last	$rndkey0,$inout3
	aes${dir}last	$rndkey0,$inout4
	aes${dir}last	$rndkey0,$inout5
	ret
.size	_aesni_${dir}rypt6,.-_aesni_${dir}rypt6
___
}
sub aesni_generate8 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-7] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt8,\@abi-omnipotent
.align	16
_aesni_${dir}rypt8:
	$movkey		($key),$rndkey0
	shr		\$1,$rounds
	$movkey		16($key),$rndkey1
	lea		32($key),$key
	xorps		$rndkey0,$inout0
	xorps		$rndkey0,$inout1
	aes${dir}	$rndkey1,$inout0
	pxor		$rndkey0,$inout2
	aes${dir}	$rndkey1,$inout1
	pxor		$rndkey0,$inout3
	aes${dir}	$rndkey1,$inout2
	pxor		$rndkey0,$inout4
	aes${dir}	$rndkey1,$inout3
	pxor		$rndkey0,$inout5
	dec		$rounds
	aes${dir}	$rndkey1,$inout4
	pxor		$rndkey0,$inout6
	aes${dir}	$rndkey1,$inout5
	pxor		$rndkey0,$inout7
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout6
	aes${dir}	$rndkey1,$inout7
	$movkey		16($key),$rndkey1
	jmp		.L${dir}_loop8_enter
.align	16
.L${dir}_loop8:
	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey1,$inout4
	aes${dir}	$rndkey1,$inout5
	aes${dir}	$rndkey1,$inout6
	aes${dir}	$rndkey1,$inout7
	$movkey		16($key),$rndkey1
.L${dir}_loop8_enter:				# happens to be 16-byte aligned
	aes${dir}	$rndkey0,$inout0
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	aes${dir}	$rndkey0,$inout3
	aes${dir}	$rndkey0,$inout4
	aes${dir}	$rndkey0,$inout5
	aes${dir}	$rndkey0,$inout6
	aes${dir}	$rndkey0,$inout7
	$movkey		($key),$rndkey0
	jnz		.L${dir}_loop8

	aes${dir}	$rndkey1,$inout0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey1,$inout4
	aes${dir}	$rndkey1,$inout5
	aes${dir}	$rndkey1,$inout6
	aes${dir}	$rndkey1,$inout7
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	aes${dir}last	$rndkey0,$inout3
	aes${dir}last	$rndkey0,$inout4
	aes${dir}last	$rndkey0,$inout5
	aes${dir}last	$rndkey0,$inout6
	aes${dir}last	$rndkey0,$inout7
	ret
.size	_aesni_${dir}rypt8,.-_aesni_${dir}rypt8
___
}
&aesni_generate3("enc") if ($PREFIX eq "aesni");
&aesni_generate3("dec");
&aesni_generate4("enc") if ($PREFIX eq "aesni");
&aesni_generate4("dec");
&aesni_generate6("enc") if ($PREFIX eq "aesni");
&aesni_generate6("dec");
&aesni_generate8("enc") if ($PREFIX eq "aesni");
&aesni_generate8("dec");

if ($PREFIX eq "aesni") {
########################################################################
# void aesni_ecb_encrypt (const void *in, void *out,
#			  size_t length, const AES_KEY *key,
#			  int enc);
$code.=<<___;
.globl	aesni_ecb_encrypt
.type	aesni_ecb_encrypt,\@function,5
.align	16
aesni_ecb_encrypt:
	and	\$-16,$len
	jz	.Lecb_ret

	mov	240($key),$rounds	# key->rounds
	$movkey	($key),$rndkey0
	mov	$key,$key_		# backup $key
	mov	$rounds,$rnds_		# backup $rounds
	test	%r8d,%r8d		# 5th argument
	jz	.Lecb_decrypt
#--------------------------- ECB ENCRYPT ------------------------------#
	cmp	\$0x80,$len
	jb	.Lecb_enc_tail

	movdqu	($inp),$inout0
	movdqu	0x10($inp),$inout1
	movdqu	0x20($inp),$inout2
	movdqu	0x30($inp),$inout3
	movdqu	0x40($inp),$inout4
	movdqu	0x50($inp),$inout5
	movdqu	0x60($inp),$inout6
	movdqu	0x70($inp),$inout7
	lea	0x80($inp),$inp
	sub	\$0x80,$len
	jmp	.Lecb_enc_loop8_enter
.align 16
.Lecb_enc_loop8:
	movups	$inout0,($out)
	mov	$key_,$key		# restore $key
	movdqu	($inp),$inout0
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout1,0x10($out)
	movdqu	0x10($inp),$inout1
	movups	$inout2,0x20($out)
	movdqu	0x20($inp),$inout2
	movups	$inout3,0x30($out)
	movdqu	0x30($inp),$inout3
	movups	$inout4,0x40($out)
	movdqu	0x40($inp),$inout4
	movups	$inout5,0x50($out)
	movdqu	0x50($inp),$inout5
	movups	$inout6,0x60($out)
	movdqu	0x60($inp),$inout6
	movups	$inout7,0x70($out)
	lea	0x80($out),$out
	movdqu	0x70($inp),$inout7
	lea	0x80($inp),$inp
.Lecb_enc_loop8_enter:

	call	_aesni_encrypt8

	sub	\$0x80,$len
	jnc	.Lecb_enc_loop8

	movups	$inout0,($out)
	mov	$key_,$key		# restore $key
	movups	$inout1,0x10($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	movups	$inout6,0x60($out)
	movups	$inout7,0x70($out)
	lea	0x80($out),$out
	add	\$0x80,$len
	jz	.Lecb_ret

.Lecb_enc_tail:
	movups	($inp),$inout0
	cmp	\$0x20,$len
	jb	.Lecb_enc_one
	movups	0x10($inp),$inout1
	je	.Lecb_enc_two
	movups	0x20($inp),$inout2
	cmp	\$0x40,$len
	jb	.Lecb_enc_three
	movups	0x30($inp),$inout3
	je	.Lecb_enc_four
	movups	0x40($inp),$inout4
	cmp	\$0x60,$len
	jb	.Lecb_enc_five
	movups	0x50($inp),$inout5
	je	.Lecb_enc_six
	movdqu	0x60($inp),$inout6
	call	_aesni_encrypt8
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	movups	$inout6,0x60($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_one:
___
	&aesni_generate1("enc",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_two:
	xorps	$inout2,$inout2
	call	_aesni_encrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_three:
	call	_aesni_encrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_four:
	call	_aesni_encrypt4
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_five:
	xorps	$inout5,$inout5
	call	_aesni_encrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_six:
	call	_aesni_encrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	jmp	.Lecb_ret
#--------------------------- ECB DECRYPT ------------------------------#
.align	16
.Lecb_decrypt:
	cmp	\$0x80,$len
	jb	.Lecb_dec_tail

	movdqu	($inp),$inout0
	movdqu	0x10($inp),$inout1
	movdqu	0x20($inp),$inout2
	movdqu	0x30($inp),$inout3
	movdqu	0x40($inp),$inout4
	movdqu	0x50($inp),$inout5
	movdqu	0x60($inp),$inout6
	movdqu	0x70($inp),$inout7
	lea	0x80($inp),$inp
	sub	\$0x80,$len
	jmp	.Lecb_dec_loop8_enter
.align 16
.Lecb_dec_loop8:
	movups	$inout0,($out)
	mov	$key_,$key		# restore $key
	movdqu	($inp),$inout0
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout1,0x10($out)
	movdqu	0x10($inp),$inout1
	movups	$inout2,0x20($out)
	movdqu	0x20($inp),$inout2
	movups	$inout3,0x30($out)
	movdqu	0x30($inp),$inout3
	movups	$inout4,0x40($out)
	movdqu	0x40($inp),$inout4
	movups	$inout5,0x50($out)
	movdqu	0x50($inp),$inout5
	movups	$inout6,0x60($out)
	movdqu	0x60($inp),$inout6
	movups	$inout7,0x70($out)
	lea	0x80($out),$out
	movdqu	0x70($inp),$inout7
	lea	0x80($inp),$inp
.Lecb_dec_loop8_enter:

	call	_aesni_decrypt8

	$movkey	($key_),$rndkey0
	sub	\$0x80,$len
	jnc	.Lecb_dec_loop8

	movups	$inout0,($out)
	mov	$key_,$key		# restore $key
	movups	$inout1,0x10($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	movups	$inout6,0x60($out)
	movups	$inout7,0x70($out)
	lea	0x80($out),$out
	add	\$0x80,$len
	jz	.Lecb_ret

.Lecb_dec_tail:
	movups	($inp),$inout0
	cmp	\$0x20,$len
	jb	.Lecb_dec_one
	movups	0x10($inp),$inout1
	je	.Lecb_dec_two
	movups	0x20($inp),$inout2
	cmp	\$0x40,$len
	jb	.Lecb_dec_three
	movups	0x30($inp),$inout3
	je	.Lecb_dec_four
	movups	0x40($inp),$inout4
	cmp	\$0x60,$len
	jb	.Lecb_dec_five
	movups	0x50($inp),$inout5
	je	.Lecb_dec_six
	movups	0x60($inp),$inout6
	$movkey	($key),$rndkey0
	call	_aesni_decrypt8
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	movups	$inout6,0x60($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_one:
___
	&aesni_generate1("dec",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_two:
	xorps	$inout2,$inout2
	call	_aesni_decrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_three:
	call	_aesni_decrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_four:
	call	_aesni_decrypt4
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_five:
	xorps	$inout5,$inout5
	call	_aesni_decrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_six:
	call	_aesni_decrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)

.Lecb_ret:
	ret
.size	aesni_ecb_encrypt,.-aesni_ecb_encrypt
___
}

# void $PREFIX_cbc_encrypt (const void *inp, void *out,
#			    size_t length, const AES_KEY *key,
#			    unsigned char *ivp,const int enc);
{
my $reserved = $win64?0x40:-0x18;	# used in decrypt
$code.=<<___;
.globl	${PREFIX}_cbc_encrypt
.type	${PREFIX}_cbc_encrypt,\@function,6
.align	16
${PREFIX}_cbc_encrypt:
	test	$len,$len		# check length
	jz	.Lcbc_ret

	mov	240($key),$rnds_	# key->rounds
	mov	$key,$key_		# backup $key
	test	%r9d,%r9d		# 6th argument
	jz	.Lcbc_decrypt
#--------------------------- CBC ENCRYPT ------------------------------#
	movups	($ivp),$inout0		# load iv as initial state
	mov	$rnds_,$rounds
	cmp	\$16,$len
	jb	.Lcbc_enc_tail
	sub	\$16,$len
	jmp	.Lcbc_enc_loop
.align	16
.Lcbc_enc_loop:
	movups	($inp),$inout1		# load input
	lea	16($inp),$inp
	#xorps	$inout1,$inout0
___
	&aesni_generate1("enc",$key,$rounds,$inout0,$inout1);
$code.=<<___;
	mov	$rnds_,$rounds		# restore $rounds
	mov	$key_,$key		# restore $key
	movups	$inout0,0($out)		# store output
	lea	16($out),$out
	sub	\$16,$len
	jnc	.Lcbc_enc_loop
	add	\$16,$len
	jnz	.Lcbc_enc_tail
	movups	$inout0,($ivp)
	jmp	.Lcbc_ret

.Lcbc_enc_tail:
	mov	$len,%rcx	# zaps $key
	xchg	$inp,$out	# $inp is %rsi and $out is %rdi now
	.long	0x9066A4F3	# rep movsb
	mov	\$16,%ecx	# zero tail
	sub	$len,%rcx
	xor	%eax,%eax
	.long	0x9066AAF3	# rep stosb
	lea	-16(%rdi),%rdi	# rewind $out by 1 block
	mov	$rnds_,$rounds	# restore $rounds
	mov	%rdi,%rsi	# $inp and $out are the same
	mov	$key_,$key	# restore $key
	xor	$len,$len	# len=16
	jmp	.Lcbc_enc_loop	# one more spin
#--------------------------- CBC DECRYPT ------------------------------#
.align	16
.Lcbc_decrypt:
___
$code.=<<___ if ($win64);
	lea	-0x58(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,0x10(%rsp)
	movaps	%xmm8,0x20(%rsp)
	movaps	%xmm9,0x30(%rsp)
.Lcbc_decrypt_body:
___
$code.=<<___;
	movups	($ivp),$iv
	mov	$rnds_,$rounds
	cmp	\$0x70,$len
	jbe	.Lcbc_dec_tail
	shr	\$1,$rnds_
	sub	\$0x70,$len
	mov	$rnds_,$rounds
	movaps	$iv,$reserved(%rsp)
	jmp	.Lcbc_dec_loop8_enter
.align	16
.Lcbc_dec_loop8:
	movaps	$rndkey0,$reserved(%rsp)	# save IV
	movups	$inout7,($out)
	lea	0x10($out),$out
.Lcbc_dec_loop8_enter:
	$movkey		($key),$rndkey0
	movups	($inp),$inout0			# load input
	movups	0x10($inp),$inout1
	$movkey		16($key),$rndkey1

	lea		32($key),$key
	movdqu	0x20($inp),$inout2
	xorps		$rndkey0,$inout0
	movdqu	0x30($inp),$inout3
	xorps		$rndkey0,$inout1
	movdqu	0x40($inp),$inout4
	aesdec		$rndkey1,$inout0
	pxor		$rndkey0,$inout2
	movdqu	0x50($inp),$inout5
	aesdec		$rndkey1,$inout1
	pxor		$rndkey0,$inout3
	movdqu	0x60($inp),$inout6
	aesdec		$rndkey1,$inout2
	pxor		$rndkey0,$inout4
	movdqu	0x70($inp),$inout7
	aesdec		$rndkey1,$inout3
	pxor		$rndkey0,$inout5
	dec		$rounds
	aesdec		$rndkey1,$inout4
	pxor		$rndkey0,$inout6
	aesdec		$rndkey1,$inout5
	pxor		$rndkey0,$inout7
	$movkey		($key),$rndkey0
	aesdec		$rndkey1,$inout6
	aesdec		$rndkey1,$inout7
	$movkey		16($key),$rndkey1

	call		.Ldec_loop8_enter

	movups	($inp),$rndkey1		# re-load input
	movups	0x10($inp),$rndkey0
	xorps	$reserved(%rsp),$inout0	# ^= IV
	xorps	$rndkey1,$inout1
	movups	0x20($inp),$rndkey1
	xorps	$rndkey0,$inout2
	movups	0x30($inp),$rndkey0
	xorps	$rndkey1,$inout3
	movups	0x40($inp),$rndkey1
	xorps	$rndkey0,$inout4
	movups	0x50($inp),$rndkey0
	xorps	$rndkey1,$inout5
	movups	0x60($inp),$rndkey1
	xorps	$rndkey0,$inout6
	movups	0x70($inp),$rndkey0	# IV
	xorps	$rndkey1,$inout7
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout4,0x40($out)
	mov	$key_,$key		# restore $key
	movups	$inout5,0x50($out)
	lea	0x80($inp),$inp
	movups	$inout6,0x60($out)
	lea	0x70($out),$out
	sub	\$0x80,$len
	ja	.Lcbc_dec_loop8

	movaps	$inout7,$inout0
	movaps	$rndkey0,$iv
	add	\$0x70,$len
	jle	.Lcbc_dec_tail_collected
	movups	$inout0,($out)
	lea	1($rnds_,$rnds_),$rounds
	lea	0x10($out),$out
.Lcbc_dec_tail:
	movups	($inp),$inout0
	movaps	$inout0,$in0
	cmp	\$0x10,$len
	jbe	.Lcbc_dec_one

	movups	0x10($inp),$inout1
	movaps	$inout1,$in1
	cmp	\$0x20,$len
	jbe	.Lcbc_dec_two

	movups	0x20($inp),$inout2
	movaps	$inout2,$in2
	cmp	\$0x30,$len
	jbe	.Lcbc_dec_three

	movups	0x30($inp),$inout3
	cmp	\$0x40,$len
	jbe	.Lcbc_dec_four

	movups	0x40($inp),$inout4
	cmp	\$0x50,$len
	jbe	.Lcbc_dec_five

	movups	0x50($inp),$inout5
	cmp	\$0x60,$len
	jbe	.Lcbc_dec_six

	movups	0x60($inp),$inout6
	movaps	$iv,$reserved(%rsp)	# save IV
	call	_aesni_decrypt8
	movups	($inp),$rndkey1
	movups	0x10($inp),$rndkey0
	xorps	$reserved(%rsp),$inout0	# ^= IV
	xorps	$rndkey1,$inout1
	movups	0x20($inp),$rndkey1
	xorps	$rndkey0,$inout2
	movups	0x30($inp),$rndkey0
	xorps	$rndkey1,$inout3
	movups	0x40($inp),$rndkey1
	xorps	$rndkey0,$inout4
	movups	0x50($inp),$rndkey0
	xorps	$rndkey1,$inout5
	movups	0x60($inp),$iv		# IV
	xorps	$rndkey0,$inout6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	lea	0x60($out),$out
	movaps	$inout6,$inout0
	sub	\$0x70,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_one:
___
	&aesni_generate1("dec",$key,$rounds);
$code.=<<___;
	xorps	$iv,$inout0
	movaps	$in0,$iv
	sub	\$0x10,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_two:
	xorps	$inout2,$inout2
	call	_aesni_decrypt3
	xorps	$iv,$inout0
	xorps	$in0,$inout1
	movups	$inout0,($out)
	movaps	$in1,$iv
	movaps	$inout1,$inout0
	lea	0x10($out),$out
	sub	\$0x20,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_three:
	call	_aesni_decrypt3
	xorps	$iv,$inout0
	xorps	$in0,$inout1
	movups	$inout0,($out)
	xorps	$in1,$inout2
	movups	$inout1,0x10($out)
	movaps	$in2,$iv
	movaps	$inout2,$inout0
	lea	0x20($out),$out
	sub	\$0x30,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_four:
	call	_aesni_decrypt4
	xorps	$iv,$inout0
	movups	0x30($inp),$iv
	xorps	$in0,$inout1
	movups	$inout0,($out)
	xorps	$in1,$inout2
	movups	$inout1,0x10($out)
	xorps	$in2,$inout3
	movups	$inout2,0x20($out)
	movaps	$inout3,$inout0
	lea	0x30($out),$out
	sub	\$0x40,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_five:
	xorps	$inout5,$inout5
	call	_aesni_decrypt6
	movups	0x10($inp),$rndkey1
	movups	0x20($inp),$rndkey0
	xorps	$iv,$inout0
	xorps	$in0,$inout1
	xorps	$rndkey1,$inout2
	movups	0x30($inp),$rndkey1
	xorps	$rndkey0,$inout3
	movups	0x40($inp),$iv
	xorps	$rndkey1,$inout4
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	lea	0x40($out),$out
	movaps	$inout4,$inout0
	sub	\$0x50,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_six:
	call	_aesni_decrypt6
	movups	0x10($inp),$rndkey1
	movups	0x20($inp),$rndkey0
	xorps	$iv,$inout0
	xorps	$in0,$inout1
	xorps	$rndkey1,$inout2
	movups	0x30($inp),$rndkey1
	xorps	$rndkey0,$inout3
	movups	0x40($inp),$rndkey0
	xorps	$rndkey1,$inout4
	movups	0x50($inp),$iv
	xorps	$rndkey0,$inout5
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	lea	0x50($out),$out
	movaps	$inout5,$inout0
	sub	\$0x60,$len
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_tail_collected:
	and	\$15,$len
	movups	$iv,($ivp)
	jnz	.Lcbc_dec_tail_partial
	movups	$inout0,($out)
	jmp	.Lcbc_dec_ret
.align	16
.Lcbc_dec_tail_partial:
	movaps	$inout0,$reserved(%rsp)
	mov	\$16,%rcx
	mov	$out,%rdi
	sub	$len,%rcx
	lea	$reserved(%rsp),%rsi
	.long	0x9066A4F3	# rep movsb

.Lcbc_dec_ret:
___
$code.=<<___ if ($win64);
	movaps	(%rsp),%xmm6
	movaps	0x10(%rsp),%xmm7
	movaps	0x20(%rsp),%xmm8
	movaps	0x30(%rsp),%xmm9
	lea	0x58(%rsp),%rsp
___
$code.=<<___;
.Lcbc_ret:
	ret
.size	${PREFIX}_cbc_encrypt,.-${PREFIX}_cbc_encrypt
___
} 
# int $PREFIX_set_[en|de]crypt_key (const unsigned char *userKey,
#				int bits, AES_KEY *key)
{ my ($inp,$bits,$key) = @_4args;
  $bits =~ s/%r/%e/;

$code.=<<___;
.globl	${PREFIX}_set_decrypt_key
.type	${PREFIX}_set_decrypt_key,\@abi-omnipotent
.align	16
${PREFIX}_set_decrypt_key:
	.byte	0x48,0x83,0xEC,0x08	# sub rsp,8
	call	__aesni_set_encrypt_key
	shl	\$4,$bits		# rounds-1 after _aesni_set_encrypt_key
	test	%eax,%eax
	jnz	.Ldec_key_ret
	lea	16($key,$bits),$inp	# points at the end of key schedule

	$movkey	($key),%xmm0		# just swap
	$movkey	($inp),%xmm1
	$movkey	%xmm0,($inp)
	$movkey	%xmm1,($key)
	lea	16($key),$key
	lea	-16($inp),$inp

.Ldec_key_inverse:
	$movkey	($key),%xmm0		# swap and inverse
	$movkey	($inp),%xmm1
	aesimc	%xmm0,%xmm0
	aesimc	%xmm1,%xmm1
	lea	16($key),$key
	lea	-16($inp),$inp
	$movkey	%xmm0,16($inp)
	$movkey	%xmm1,-16($key)
	cmp	$key,$inp
	ja	.Ldec_key_inverse

	$movkey	($key),%xmm0		# inverse middle
	aesimc	%xmm0,%xmm0
	$movkey	%xmm0,($inp)
.Ldec_key_ret:
	add	\$8,%rsp
	ret
.LSEH_end_set_decrypt_key:
.size	${PREFIX}_set_decrypt_key,.-${PREFIX}_set_decrypt_key
___

# This is based on submission by
#
#	Huang Ying <ying.huang@intel.com>
#	Vinodh Gopal <vinodh.gopal@intel.com>
#	Kahraman Akdemir
#
# Agressively optimized in respect to aeskeygenassist's critical path
# and is contained in %xmm0-5 to meet Win64 ABI requirement.
#
$code.=<<___;
.globl	${PREFIX}_set_encrypt_key
.type	${PREFIX}_set_encrypt_key,\@abi-omnipotent
.align	16
${PREFIX}_set_encrypt_key:
__aesni_set_encrypt_key:
	.byte	0x48,0x83,0xEC,0x08	# sub rsp,8
	mov	\$-1,%rax
	test	$inp,$inp
	jz	.Lenc_key_ret
	test	$key,$key
	jz	.Lenc_key_ret

	movups	($inp),%xmm0		# pull first 128 bits of *userKey
	xorps	%xmm4,%xmm4		# low dword of xmm4 is assumed 0
	lea	16($key),%rax
	cmp	\$256,$bits
	je	.L14rounds
	cmp	\$192,$bits
	je	.L12rounds
	cmp	\$128,$bits
	jne	.Lbad_keybits

.L10rounds:
	mov	\$9,$bits			# 10 rounds for 128-bit key
	$movkey	%xmm0,($key)			# round 0
	aeskeygenassist	\$0x1,%xmm0,%xmm1	# round 1
	call		.Lkey_expansion_128_cold
	aeskeygenassist	\$0x2,%xmm0,%xmm1	# round 2
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x4,%xmm0,%xmm1	# round 3
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x8,%xmm0,%xmm1	# round 4
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x10,%xmm0,%xmm1	# round 5
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x20,%xmm0,%xmm1	# round 6
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x40,%xmm0,%xmm1	# round 7
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x80,%xmm0,%xmm1	# round 8
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x1b,%xmm0,%xmm1	# round 9
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x36,%xmm0,%xmm1	# round 10
	call		.Lkey_expansion_128
	$movkey	%xmm0,(%rax)
	mov	$bits,80(%rax)	# 240(%rdx)
	xor	%eax,%eax
	jmp	.Lenc_key_ret

.align	16
.L12rounds:
	movq	16($inp),%xmm2			# remaining 1/3 of *userKey
	mov	\$11,$bits			# 12 rounds for 192
	$movkey	%xmm0,($key)			# round 0
	aeskeygenassist	\$0x1,%xmm2,%xmm1	# round 1,2
	call		.Lkey_expansion_192a_cold
	aeskeygenassist	\$0x2,%xmm2,%xmm1	# round 2,3
	call		.Lkey_expansion_192b
	aeskeygenassist	\$0x4,%xmm2,%xmm1	# round 4,5
	call		.Lkey_expansion_192a
	aeskeygenassist	\$0x8,%xmm2,%xmm1	# round 5,6
	call		.Lkey_expansion_192b
	aeskeygenassist	\$0x10,%xmm2,%xmm1	# round 7,8
	call		.Lkey_expansion_192a
	aeskeygenassist	\$0x20,%xmm2,%xmm1	# round 8,9
	call		.Lkey_expansion_192b
	aeskeygenassist	\$0x40,%xmm2,%xmm1	# round 10,11
	call		.Lkey_expansion_192a
	aeskeygenassist	\$0x80,%xmm2,%xmm1	# round 11,12
	call		.Lkey_expansion_192b
	$movkey	%xmm0,(%rax)
	mov	$bits,48(%rax)	# 240(%rdx)
	xor	%rax, %rax
	jmp	.Lenc_key_ret

.align	16
.L14rounds:
	movups	16($inp),%xmm2			# remaning half of *userKey
	mov	\$13,$bits			# 14 rounds for 256
	lea	16(%rax),%rax
	$movkey	%xmm0,($key)			# round 0
	$movkey	%xmm2,16($key)			# round 1
	aeskeygenassist	\$0x1,%xmm2,%xmm1	# round 2
	call		.Lkey_expansion_256a_cold
	aeskeygenassist	\$0x1,%xmm0,%xmm1	# round 3
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x2,%xmm2,%xmm1	# round 4
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x2,%xmm0,%xmm1	# round 5
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x4,%xmm2,%xmm1	# round 6
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x4,%xmm0,%xmm1	# round 7
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x8,%xmm2,%xmm1	# round 8
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x8,%xmm0,%xmm1	# round 9
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x10,%xmm2,%xmm1	# round 10
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x10,%xmm0,%xmm1	# round 11
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x20,%xmm2,%xmm1	# round 12
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x20,%xmm0,%xmm1	# round 13
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x40,%xmm2,%xmm1	# round 14
	call		.Lkey_expansion_256a
	$movkey	%xmm0,(%rax)
	mov	$bits,16(%rax)	# 240(%rdx)
	xor	%rax,%rax
	jmp	.Lenc_key_ret

.align	16
.Lbad_keybits:
	mov	\$-2,%rax
.Lenc_key_ret:
	add	\$8,%rsp
	ret
.LSEH_end_set_encrypt_key:

.align	16
.Lkey_expansion_128:
	$movkey	%xmm0,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_128_cold:
	shufps	\$0b00010000,%xmm0,%xmm4
	xorps	%xmm4, %xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	xorps	%xmm4, %xmm0
	shufps	\$0b11111111,%xmm1,%xmm1	# critical path
	xorps	%xmm1,%xmm0
	ret

.align 16
.Lkey_expansion_192a:
	$movkey	%xmm0,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_192a_cold:
	movaps	%xmm2, %xmm5
.Lkey_expansion_192b_warm:
	shufps	\$0b00010000,%xmm0,%xmm4
	movdqa	%xmm2,%xmm3
	xorps	%xmm4,%xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	pslldq	\$4,%xmm3
	xorps	%xmm4,%xmm0
	pshufd	\$0b01010101,%xmm1,%xmm1	# critical path
	pxor	%xmm3,%xmm2
	pxor	%xmm1,%xmm0
	pshufd	\$0b11111111,%xmm0,%xmm3
	pxor	%xmm3,%xmm2
	ret

.align 16
.Lkey_expansion_192b:
	movaps	%xmm0,%xmm3
	shufps	\$0b01000100,%xmm0,%xmm5
	$movkey	%xmm5,(%rax)
	shufps	\$0b01001110,%xmm2,%xmm3
	$movkey	%xmm3,16(%rax)
	lea	32(%rax),%rax
	jmp	.Lkey_expansion_192b_warm

.align	16
.Lkey_expansion_256a:
	$movkey	%xmm2,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_256a_cold:
	shufps	\$0b00010000,%xmm0,%xmm4
	xorps	%xmm4,%xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	xorps	%xmm4,%xmm0
	shufps	\$0b11111111,%xmm1,%xmm1	# critical path
	xorps	%xmm1,%xmm0
	ret

.align 16
.Lkey_expansion_256b:
	$movkey	%xmm0,(%rax)
	lea	16(%rax),%rax

	shufps	\$0b00010000,%xmm2,%xmm4
	xorps	%xmm4,%xmm2
	shufps	\$0b10001100,%xmm2,%xmm4
	xorps	%xmm4,%xmm2
	shufps	\$0b10101010,%xmm1,%xmm1	# critical path
	xorps	%xmm1,%xmm2
	ret
.size	${PREFIX}_set_encrypt_key,.-${PREFIX}_set_encrypt_key
.size	__aesni_set_encrypt_key,.-__aesni_set_encrypt_key
___
}

$code.=<<___;
.align	64
.Lbswap_mask:
	.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.Lincrement32:
	.long	6,6,6,0
.Lincrement64:
	.long	1,0,0,0
.Lxts_magic:
	.long	0x87,0,1,0

.asciz  "AES for Intel AES-NI, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	cbc_se_handler,\@abi-omnipotent
.align	16
cbc_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	152($context),%rax	# pull context->Rsp
	mov	248($context),%rbx	# pull context->Rip

	lea	.Lcbc_decrypt(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<"prologue" label
	jb	.Lin_prologue

	lea	.Lcbc_decrypt_body(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<cbc_decrypt_body
	jb	.Lrestore_rax

	lea	.Lcbc_ret(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>="epilogue" label
	jae	.Lin_prologue

	lea	0(%rax),%rsi		# top of stack
	lea	512($context),%rdi	# &context.Xmm6
	mov	\$8,%ecx		# 4*sizeof(%xmm0)/sizeof(%rax)
	.long	0xa548f3fc		# cld; rep movsq
	lea	0x58(%rax),%rax		# adjust stack pointer
	jmp	.Lin_prologue

.Lrestore_rax:
	mov	120($context),%rax
.Lin_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	jmp	.Lcommon_seh_exit
.size	cbc_se_handler,.-cbc_se_handler

.type	ecb_se_handler,\@abi-omnipotent
.align	16
ecb_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	152($context),%rax	# pull context->Rsp
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

.Lcommon_seh_exit:

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	cbc_se_handler,.-cbc_se_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_${PREFIX}_ecb_encrypt
	.rva	.LSEH_end_${PREFIX}_ecb_encrypt
	.rva	.LSEH_info_ecb

	.rva	.LSEH_begin_${PREFIX}_cbc_encrypt
	.rva	.LSEH_end_${PREFIX}_cbc_encrypt
	.rva	.LSEH_info_cbc

	.rva	${PREFIX}_set_decrypt_key
	.rva	.LSEH_end_set_decrypt_key
	.rva	.LSEH_info_key

	.rva	${PREFIX}_set_encrypt_key
	.rva	.LSEH_end_set_encrypt_key
	.rva	.LSEH_info_key
.section	.xdata
.align	8
.LSEH_info_ecb:
	.byte	9,0,0,0
	.rva	ecb_se_handler
.LSEH_info_cbc:
	.byte	9,0,0,0
	.rva	cbc_se_handler
.LSEH_info_key:
	.byte	0x01,0x04,0x01,0x00
	.byte	0x04,0x02,0x00,0x00
___
}

sub rex {
 local *opcode=shift;
 my ($dst,$src)=@_;

   if ($dst>=8 || $src>=8) {
	$rex=0x40;
	$rex|=0x04 if($dst>=8);
	$rex|=0x01 if($src>=8);
	push @opcode,$rex;
   }
}

sub aesni {
  my $line=shift;
  my @opcode=(0x66);

    if ($line=~/(aeskeygenassist)\s+\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
	rex(\@opcode,$4,$3);
	push @opcode,0x0f,0x3a,0xdf;
	push @opcode,0xc0|($3&7)|(($4&7)<<3);	# ModR/M
	my $c=$2;
	push @opcode,$c=~/^0/?oct($c):$c;
	return ".byte\t".join(',',@opcode);
    }
    elsif ($line=~/(aes[a-z]+)\s+%xmm([0-9]+),\s*%xmm([0-9]+)/) {
	my %opcodelet = (
		"aesimc" => 0xdb,
		"aesenc" => 0xdc,	"aesenclast" => 0xdd,
		"aesdec" => 0xde,	"aesdeclast" => 0xdf
	);
	return undef if (!defined($opcodelet{$1}));
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x38,$opcodelet{$1};
	push @opcode,0xc0|($2&7)|(($3&7)<<3);	# ModR/M
	return ".byte\t".join(',',@opcode);
    }
    return $line;
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;
$code =~ s/\b(aes.*%xmm[0-9]+).*$/aesni($1)/gem;

print $code;

close STDOUT;
