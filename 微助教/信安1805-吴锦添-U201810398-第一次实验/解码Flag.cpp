#define _CRT_SECURE_NO_WARNINGS
#include<bits/stdc++.h>
using namespace std;

int main() {
	const char* a = "invalid argument";
	int l = strlen(a);
	char Flag[100];
	memset(Flag, 0, sizeof(Flag));
	for (int i = 0; i < l; i++) {
		Flag[i] = (*(a + i)) ^ 0x1Cu;
		cout << Flag[i];
	}
	cout << endl;
	for (int i = 0; i < l; i++) {	
		Flag[i] = Flag[i] ^ 0x1Fu;
		cout << Flag[i];
	}
	cout << endl;
	Flag[7] = 'A';
	cout << Flag << endl;

	return 0;
}