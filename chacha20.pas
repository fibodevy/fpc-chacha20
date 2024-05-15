unit chacha20;

// ChaCha20 version with 96 bit nonce
// Copyright (c) 2024 fibodevy https://github.com/fibodevy
// License: MIT

{$mode ObjFPC}{$H+}

interface

type
  chacha20state = packed record
    state: array[0..15] of dword;
    keystream: array[0..15] of dword;
    position: uint8;
  end;

function chacha20_init(var state: chacha20state; key, nonce: string; counter: dword=0): boolean;
procedure chacha20_set_counter(var state: chacha20state; counter: dword);
procedure chacha20_xor(var state: chacha20state; p: pointer; l: dword);

implementation

function rotl32(x, n: dword): dword; inline;
begin
  result := (x shl n) or (x shr (32-n));
end;

procedure CHACHA20_QUARTERROUND(p: pointer; a, b, c, d: dword); inline;
type
  t = array[0..15] of dword;
var
	x: ^t;
begin
  x := p;
  x^[a] += x^[b]; x^[d] := rotl32(x^[d] xor x^[a], 16);
  x^[c] += x^[d]; x^[b] := rotl32(x^[b] xor x^[c], 12);
  x^[a] += x^[b]; x^[d] := rotl32(x^[d] xor x^[a], 8);
  x^[c] += x^[d]; x^[b] := rotl32(x^[b] xor x^[c], 7);
end;

function chacha20_init(var state: chacha20state; key, nonce: string; counter: dword=0): boolean;
const
  magic = 'expand 32-byte k';
begin
  result := false;

  fillchar(state, sizeof(state), 0);

	// magic 16 bytes
  move(magic[1], state.state[0], 16);

  // key 32 bytes; if longer then cut it
  if length(key) > 32 then setlength(key, 32);
  if key <> '' then move(key[1], state.state[4], length(key));

  // nonce 12 bytes; if longer then cut it
  if length(nonce) > 12 then setlength(nonce, 12);
  if nonce <> '' then move(nonce[1], state.state[13], length(nonce));

  // counter
  chacha20_set_counter(state, counter);

  result := true;
end;

procedure chacha20_set_counter(var state: chacha20state; counter: dword);
begin
  move(counter, state.state[12], sizeof(counter));
  state.position := 64;
end;

procedure cha20_next_block(var state: chacha20state);
var
  i: integer;
begin
  // copy state to keystream
  move(state.state, state.keystream, 64);

  // mix the bytes a lot and hope that nobody finds out how to undo it
	for i := 1 to 10 do begin
		CHACHA20_QUARTERROUND(@state.keystream, 0, 4, 8, 12);
		CHACHA20_QUARTERROUND(@state.keystream, 1, 5, 9, 13);
		CHACHA20_QUARTERROUND(@state.keystream, 2, 6, 10, 14);
		CHACHA20_QUARTERROUND(@state.keystream, 3, 7, 11, 15);
		CHACHA20_QUARTERROUND(@state.keystream, 0, 5, 10, 15);
		CHACHA20_QUARTERROUND(@state.keystream, 1, 6, 11, 12);
		CHACHA20_QUARTERROUND(@state.keystream, 2, 7, 8, 13);
		CHACHA20_QUARTERROUND(@state.keystream, 3, 4, 9, 14);
  end;

  // add state dwords to keystream dwords
  for i := 0 to high(state.keystream) do state.keystream[i] += state.state[i];

  // increase counter
  inc(state.state[12]);

  // reset position
  state.position := 0;
end;

procedure chacha20_xor(var state: chacha20state; p: pointer; l: dword);
var
  i: integer;
begin
  for i := 0 to l-1 do begin
    if state.position >= 64 then cha20_next_block(state);
    pbyte(p+i)^ := pbyte(p+i)^ xor pbyte(@state.keystream[0]+state.position)^;
    inc(state.position);
  end;
end;

end.

