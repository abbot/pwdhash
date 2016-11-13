import pwdhash
import unittest

class TestGeneratedPasswords(unittest.TestCase):

		def test_domains(self):
				master = "hello"
				pwd = pwdhash.generate(master, "example.com")
				for domain in ("1.example.com", "2.example.com", "3.2.example.com"):
						self.assertEqual(pwd, pwdhash.generate(master, domain))

		def test_generate(self):
				passwords = {
						"a": "9FBo",
						"aB": "4BMm",
						"aB1": "Js0Ad",
						"aB1.": "+4wVkg",
						"aBc1.": "+J5MEzq",
				}
				domain = "example.com"
				for master, pwd in passwords.items():
						t = pwdhash.generate(master, domain)
						self.assertEqual(pwd, t,
								"password for master %r doesn't match: %r != %r" % (master, pwd, t))

		def test_applyconstraints(self):
				self.assertEqual(pwdhash.apply_constraints("5vY9jidbW9wPvvubi1ilRw", 3, False),
						"9FBo")

if __name__ == '__main__':
		unittest.main()