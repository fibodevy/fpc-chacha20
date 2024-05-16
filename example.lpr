program example;

uses chacha20;

var
  s: string;
  cc: chacha20state;

begin
  // key should be 32 bytes, nonce 12 bytes
  chacha20_init(cc, 'key', 'nonce');

  s := 'hello';
  s := copy(s, 1); // make string memory writable

  // encrypt
  chacha20_xor(cc, @s[1], length(s));
  writeln('encrypted = ', s);

  // decrypt
  chacha20_set_counter(cc, 0);
  chacha20_xor(cc, @s[1], length(s));
  writeln('decrypted = ', s);

  readln;
end.

