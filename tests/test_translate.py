from anlat import translate

MARK = {"ANLT-aaaa1111": "saved browser password for shop.example.test"}

TRACE = '''123 openat(AT_FDCWD, "/home/user/.config/google-chrome/Default/Login Data", O_RDONLY) = 3
123 read(3, "pw-ANLT-aaaa1111", 4096) = 16
123 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH
123 sendto(4, "POST /x pw-ANLT-aaaa1111", 30, 0, NULL, 0) = -1 ENETUNREACH
'''


def test_detects_theft():
    score, findings, stolen = translate.analyze(TRACE, MARK, "en")
    assert score >= 60
    assert stolen == [("saved browser password for shop.example.test", True)]
    assert any("passwords" in f for f in findings)


def test_clean():
    score, findings, stolen = translate.analyze('1 execve("/tmp/target", [], 0) = 0\n', MARK)
    assert score == 0 and not stolen
