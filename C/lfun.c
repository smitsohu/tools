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

        FIXME this code doesn't know about string literal concatenation

**************************************************/


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ftw.h>

#define FUNCTION "strncmp"	// function name
#define ARGCNT 3		// number of function arguments, >= 2
// scan only files with certain extensions
#define CHECKEXTENSION ".c", ".cc", ".cpp"

#define MAXBUF 4096
size_t arr[ARGCNT];
unsigned calls = 0;
unsigned loc = 0;
int boring = 1;


// return 0 if parsing was successful, else return 1
int parse_args(const char *path, const unsigned linecnt, const char *fcall) {

	// proceed with a copy of the string
	char dup[MAXBUF];
	strncpy(dup, fcall, MAXBUF);
	assert(dup[MAXBUF - 1] == '\0');

	size_t arg_len[ARGCNT - 1] = {0};  // lengths of string literals go here
	char *tmp = dup + 1;  // dup[0] == '('
	int strlit = 0;
	int i;
	for (i = 0; i < ARGCNT - 1; i++) {
		dup[arr[i]] = '\0';  // comma
		while (*tmp == ' ' || *tmp == '\t')
			tmp++;
		if (*tmp == '"') {
			tmp++;
			// count escape sequences
			// and strip closing quotation mark
			// FIXME string literal concatenation
			unsigned esc = 0;
			char *ptr = tmp;
			while (*ptr) {
				if (*ptr == '\\') {
					esc++;
					if (ptr[1])  // get past the following byte, it could be '\\' or '"'
						ptr++;
				}
				else if (*ptr == '"') {
					char *end = ptr + 1;
					while (*end == ' ' || *end == '\t')
						end++;
					if (*end == '\0')
						break;
					else
						return 1;
				}
				ptr++;
			}
			if (*ptr != '"')  // no closing quotation mark
				return 1;
			*ptr = '\0';

			arg_len[i] = strlen(tmp) - esc;
			strlit = 1;
		}
		tmp = dup + arr[i] + 1;
	}

	// no string literal, nothing to do
	if (!strlit)
		return 0;

	// last argument
	dup[arr[ARGCNT - 1]] = '\0';  // last closing parenthesis
	while (*tmp == ' ' || *tmp == '\t')
		tmp++;
	if (*tmp == '(')
		return 1;
	// variable or function call?
	if (*tmp < '0' || *tmp > '9')
		return 0;
	// there is an integer, extract it
	char *endptr;
	unsigned long litlen = strtoul(tmp, &endptr, 0);
	while (*endptr == ' ' || *endptr == '\t')
		endptr++;
	if (*endptr != '\0')
		return 1;

	for (i = 0; i < ARGCNT - 1; i++) {
		if (arg_len[i] == litlen)
			return 0;
	}
	strncpy(dup, fcall, MAXBUF);  // output formatting
	dup[arr[ARGCNT - 1] + 1] = '\0';
	printf("Bad %s? %s: line %u: %s\n", FUNCTION, path, linecnt, dup);
	boring = 0;
	return 0;
}


// return 0 if parsing was successful, else return 1
int parse_str(const char *path, const unsigned linecnt, const char *fcall) {
	assert(fcall && *fcall == '(');

	// ensure that
	// * parentheses are balanced
	// * all arguments are present
	// along the way pick up relevant indices
	const char *tmp = fcall;
	unsigned cnt1 = 0;  // count unbalanced parentheses
	unsigned cnt2 = 0;  // count commas
	size_t index = 0;
	while (*tmp) {
		if (*tmp == '(')  // what we know: tmp[0] == '('
			cnt1++;
		else if (*tmp == ')') {
			cnt1--;
			if (cnt1 == 0) {
				arr[ARGCNT - 1] = index;
				break;
			}
		}
		else if (*tmp == '"') {  // ignore what's inside string literals
			tmp++;
			index++;
			while (*tmp) {
				if (*tmp == '"')
					break;
				if (*tmp == '\\' && tmp[1]) {  // get past the following byte, it could be '"'
					tmp++;
					index++;
				}
				tmp++;
				index++;
			}
			if (*tmp != '"')
				goto errout;
		}
		else if (*tmp == ',' && cnt1 == 1) {
			if (cnt2 > ARGCNT - 2)
				goto errout;
			arr[cnt2] = index;
			cnt2++;
		}

		tmp++;
		index++;
	}
	if (cnt1 || cnt2 != ARGCNT - 1)
		goto errout;

	// something like strncmp(,,)
	if (arr[0] == 1)
		goto errout;
	int i;
	for (i = 0; i < ARGCNT - 1; i++) {
		if (arr[i] + 1 == arr[i + 1])
			goto errout;
	}

	// inspect the function arguments
	if (parse_args(path, linecnt, fcall))
		goto errout;

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
	unsigned linecnt = 0;
	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, fp)) {
		linecnt++;
		char *fcall = strstr(buf, FUNCTION);
		if (fcall) {
			// remove \n
			char *newline = strrchr(fcall, '\n');
			if (newline && newline[1] == '\0')
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
				calls++;
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
	printf("%u lines, %u %s function calls\n", loc, calls, FUNCTION);
	// nothing found?
	if (boring) {
		puts("no suspicious pattern was found");
		return 0;
	}
	return 1;
}
