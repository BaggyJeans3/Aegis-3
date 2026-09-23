import re

import pytest

from ai_engine import check_re2_compatible

# Python re 는 통과하지만 Go RE2(Coraza) 는 거부하는 패턴
REJECT = [
    r"(?=.*select)union",
    r"(?!admin)\w+",
    r"(?<=id=)\d+",
    r"(?<!\\)'",
    r"(a)\1",
    r"(?>abc)",
    r"a++",
    r"\d*+",
    r"(a)?(?(1)b|c)",
    r"(?x) union \s+ select",
    r"(?a)\w+",
    r"end\Z",
    r"a{1001}",
]

# RE2 에서 유효한 패턴 (이스케이프된 괄호·백슬래시가 오탐되지 않아야 함)
ACCEPT = [
    r"(?i)union\s+select",
    r"(?i:or)\s+1=1",
    r"(?P<k>\w+)=",
    r"\(?=",
    r"\\1",
    r"\.\./",
    r"(?s)<script.*?>",
    r"a{2,1000}",
    r"(%27|')\s*or",
]


@pytest.mark.parametrize("p", REJECT)
def test_reject(p):
    re.compile(p)  # Python 은 통과함을 전제
    with pytest.raises(re.error):
        check_re2_compatible(p)


@pytest.mark.parametrize("p", ACCEPT)
def test_accept(p):
    check_re2_compatible(p)
