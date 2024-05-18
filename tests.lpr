program tests;

uses chacha20;

// test vectors for 64 bit counter version (non IETF)
// https://datatracker.ietf.org/doc/html/draft-agl-tls-chacha20poly1305-04#section-7

var
  key, nonce, hex, vect, test, s: string;
  cc: chacha20state;
  i: integer;

begin
  setlength(key, 32);
  setlength(nonce, 8);
  setlength(test, 64);

  // test vector 1
  vect := '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc'
  +'8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c'
  +'c387b669b2ee6586';
  fillchar(key[1], 32, 0); 
  fillchar(nonce[1], 8, 0);
  setlength(test, length(vect) div 2);
  fillchar(test[1], length(test), 0);
  chacha20_init(cc, key, nonce);
  chacha20_xor(cc, @test[1], length(test));
  hex := '';
  for i := 1 to length(test) do begin writestr(s, hexstr(ord(test[i]), 2)); hex += s end;
  writeln('test 1 = ', lowercase(hex) = lowercase(vect));

  // test vector 2
  vect := '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952'
  +'ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea81'
  +'7e9ad275ae546963';
  fillchar(key[1], 32, 0);
  fillchar(nonce[1], 8, 0);
  setlength(test, length(vect) div 2);
  fillchar(test[1], length(test), 0);
  pbyte(@key[32])^ := 1;
  chacha20_init(cc, key, nonce);
  chacha20_xor(cc, @test[1], length(test));
  hex := '';
  for i := 1 to length(test) do begin writestr(s, hexstr(ord(test[i]), 2)); hex += s end;
  writeln('test 2 = ', lowercase(hex) = lowercase(vect));

  // test vector 3
  vect := 'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df1'
  +'37821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e'
  +'445f41e3';
  fillchar(key[1], 32, 0);
  fillchar(nonce[1], 8, 0);
  setlength(test, length(vect) div 2);
  fillchar(test[1], length(test), 0);
  pbyte(@nonce[8])^ := 1;
  chacha20_init(cc, key, nonce);
  chacha20_xor(cc, @test[1], length(test));
  hex := '';
  for i := 1 to length(test) do begin writestr(s, hexstr(ord(test[i]), 2)); hex += s end;
  writeln('test 3 = ', lowercase(hex) = lowercase(vect));

  // test vector 4
  vect := 'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd1'
  +'38e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d'
  +'6bbdb0041b2f586b';
  fillchar(key[1], 32, 0);
  fillchar(nonce[1], 8, 0);
  setlength(test, length(vect) div 2);
  fillchar(test[1], length(test), 0);
  pbyte(@nonce[1])^ := 1;
  chacha20_init(cc, key, nonce);
  chacha20_xor(cc, @test[1], length(test));
  hex := '';
  for i := 1 to length(test) do begin writestr(s, hexstr(ord(test[i]), 2)); hex += s end;
  writeln('test 4 = ', lowercase(hex) = lowercase(vect));

  readln;
end.

