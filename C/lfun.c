/*--------------------------------------------------------------
   Copyright 2019 smitsohu, smitsohu@gmail.com

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is furnished
   to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
   PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
   OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
--------------------------------------------------------------*/


/*************************************************

        program: lfun.c
        scans *.c, *.cc and *.cpp source files for suspicious strncmp
        function calls

        use: gcc -o lfunc lfun.c; lfunc <file or directory>

        complain, if
              * at least one argument is a string literal and
              * the last argument is an integer literal and
              * the integer doesn't match the length of a string literal

**************************************************/


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ftw.h>

#define FUNCTION "strncmp"	// function name
#define ARGCNT 3		// number of function arguments, >= 2
// scan only files with certain extensions
#define CHECKEXTENSION ".c", ".cc", ".cpp"

#define MAXBUF 4096
unsigned callcnt = 0;
unsigned loc = 0;
unsigned filecnt = 0;
int boring = 1;


// return 0 if parsing was successful, else return 1
int parse_str(const char *path, const unsigned linecnt, const char *fcall) {
	assert(fcall && *fcall == '(');
	// proceed with a copy of the string
	char dup[MAXBUF];
	strncpy(dup, fcall, MAXBUF);

	size_t arg_len[ARGCNT - 1] = {0};  // lengths of string literals go here

	char *tmp = dup;
	unsigned cnt1 = 0;  // count unbalanced parentheses
	unsigned cnt2 = 0;  // count commas
	int stringlit = 0;  // found string literal or not
	while (*tmp) {

		if (*tmp == '(') { // what we know: tmp[0] == '('
			cnt1++;
		}
		else if (*tmp == ')') {
			cnt1--;
			if (cnt1 == 0)
				// too few commas
				goto errout;
		}
		else if (*tmp == '"' && cnt1 == 1) {
			// only one string length per function argument
			if (arg_len[cnt2])
				goto errout;

			stringlit = 1;
			unsigned esc = 0;  // count escape sequences
			tmp++;

			// find end of the string literal
			char *start = tmp;
			while (*tmp) {
				if (*tmp == '\\') {
					esc++;
					// get past the following byte, it could be '"'
					if (tmp[1])
						tmp++;
				}
				else if (*tmp == '"') {
					arg_len[cnt2] += (size_t) (tmp - start);
					// handle string literal concatenation
					char *q = tmp + 1;
					while (*q == ' ' || *q == '\t')
						q++;
					if (*q == '"') {
						tmp = ++q;
						start = q;
						continue;
					}
					else
						break;
				}

				tmp++;
			}
			if (*tmp != '"')
				goto errout;
			// substract escape sequences
			arg_len[cnt2] -= esc;
		}
		else if (*tmp == ',' && cnt1 == 1) {
			cnt2++;
			// the only proper exit from this loop
			if (cnt2 == ARGCNT - 1)
				break;
		}

		tmp++;
	}

	if (!stringlit)
		return 0;
	if (cnt2 != ARGCNT - 1)  // if false, *tmp == ',' is implied
		goto errout;

	// last argument
	tmp++;
	while (*tmp == ' ' || *tmp == '\t')
		tmp++;
	// variable or function call?
	if (isalpha((unsigned char) *tmp) || *tmp == '_')
		return 0;
	if (*tmp < '0' || *tmp > '9')
		goto errout;
	// there is an integer, extract it
	char *endptr;
	unsigned long len = strtoul(tmp, &endptr, 0);
	while (*endptr == ' ' || *endptr == '\t')
		endptr++;
	if (*endptr++ != ')')
		goto errout;
	// output formatting
	*endptr = '\0';

	// check if integer literal equals length of a string literal
	int i;
	for (i = 0; i < ARGCNT - 1; i++) {
		if (arg_len[i] == len)
			return 0;
	}

	printf("Bad %s? %s: line %u: %s\n", FUNCTION, path, linecnt, dup);
	boring = 0;
	return 0;

errout:
	printf("%s: line %u: cannot parse: %s\n", path, linecnt, fcall);
	boring = 0;
	return 1;
}


int read_file(const char *path, const struct stat *s, const int typeflag, struct FTW *ftwbuf) {
	assert(path);
	(void) s;
	(void) ftwbuf;
	if (typeflag == FTW_DNR || typeflag == FTW_NS)
		return 1;
	if (typeflag != FTW_F)
		return 0;
#ifdef CHECKEXTENSION
	int found = 0;
	char *end = strrchr(path, '.');
	if (end) {
		char *ext[] = {
			CHECKEXTENSION,
			NULL
		};
		int i = 0;
		while (ext[i]) {
			if (strcmp(end, ext[i]) == 0) {
				found = 1;
				break;
			}
			i++;
		}
	}
	if (!found)
		return 0;
#endif
	FILE *fp = fopen(path, "r");
	if (!fp) {
		printf("Warning: cannot read file %s\n", path);
		boring = 0;
		return 0;
	}
	// read the file
	filecnt++;
	unsigned linecnt = 0;
	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, fp)) {
		linecnt++;
		char *fcall = strstr(buf, FUNCTION);
		if (fcall) {
			// remove \n
			char *newline = strrchr(fcall, '\n');
			if (newline)
				*newline = '\0';
			// do the parsing
			int comment = 0;
			char *tmp = buf;
			do {
				// is this inside a comment?
				// /**/ is not handled
				while (tmp != fcall) {
					if (*tmp == '/' && tmp[1] == '/') {
						comment = 1;
						break;
					}
					tmp++;
				}
				if (comment)
					break;
				callcnt++;
				static size_t len = strlen(FUNCTION);
				fcall += len;
				while (*fcall == ' ' || *fcall == '\t')
					fcall++;
				if (*fcall != '(') {
					printf("%s: line %u: cannot parse: %s\n", path, linecnt, fcall);
					boring = 0;
					break;
				}
				if (parse_str(path, linecnt, fcall))
					break;
				tmp = fcall;
			} while ((fcall = strstr(fcall, FUNCTION)) != NULL);
		}
	}
	loc += linecnt;
	fclose(fp);
	return 0;
}


// return value 0: boring
int main(int argc, char **argv) {
	// usage
	if (argc != 2) {
		printf("usage: %s <file or directory>\n", argv[0]);
		return 1;
	}
	// does the file exist?
	const char *fname = argv[1];
	struct stat s;
	if (stat(fname, &s) == -1 || (!S_ISDIR(s.st_mode) && !S_ISREG(s.st_mode))) {
		printf("no file or directory %s\n", fname);
		return 1;
	}
	// do the scan
	printf("-- scanning %s\n", fname);
	int rv = nftw(fname, read_file, 8, 0);
	if (rv == 1) {
		puts("walking the directory tree failed, check your permissions ...");
		return 1;
	}
	if (rv == -1) {
		perror("nftw");
		return 1;
	}
	printf("%u file(s), %u line(s), %u %s function call(s)\n", filecnt, loc, callcnt, FUNCTION);

	// nothing found?
	if (boring) {
		puts("no suspicious pattern was found");
		return 0;
	}
	return 1;
}
