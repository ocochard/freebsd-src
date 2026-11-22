PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/fs/nfs
BINDIR=		${TESTSDIR}

ATF_TESTS_SH+=	basic_test
ATF_TESTS_SH+=	recovery_test
ATF_TESTS_SH+=	krb5_test
ATF_TESTS_SH+=	delegation_test

# Tests share the jail names, addresses and proxy port.
TEST_METADATA+=	is_exclusive="true"

${PACKAGE}FILES+=	nfs.subr
${PACKAGE}FILES+=	nfs_reset_proxy.py
${PACKAGE}FILESMODE_nfs_reset_proxy.py=	0555

.include <bsd.test.mk>
