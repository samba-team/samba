# Used in samba.tests.source_chars to ensure bi-directional text is
# caught. (make test TESTS=samba.tests.source_chars)

x = א =2
ח = n = 3

a = x  # 2 * n * m
b = א  # 2 * ח * m
c = "x#"  #  n
d = "א#"  #  ח
e = f"x{x}n{n}"
f = f"א{א}ח{ח}"

print(a)
print(b)
print(c)
print(d)
print(e)
print(f)

assert a == b
assert c == d.replace("א", "x")
assert e[1] == f[1]
assert e[3] == f[3]
