unit chacha20;

// ChaCha20 implementation for FPC
// Copyright (c) 2024 fibodevy https://github.com/fibodevy
// License: MIT

{$mode ObjFPC}{$H+}

// uncomment to use 64 bit counter and 64 bit nonce, otherwise use 32 bit counter and 96 bit nonce
//{$define COUNTER64}

interface

type
  chacha20state = packed record
    state: array[0..15] of dword;
    keystream: array[0..15] of dword;
    position: byte;
  end;

procedure chacha20_init(var state: chacha20state; key, nonce: string; counter: {$ifdef COUNTER64}qword{$else}dword{$endif}=0);
procedure chacha20_set_counter(var state: chacha20state; counter: {$ifdef COUNTER64}qword{$else}dword{$endif});
procedure chacha20_xor(var state: chacha20state; p: pointer; l: dword);

implementation

procedure chacha20_init(var state: chacha20state; key, nonce: string; counter: {$ifdef COUNTER64}qword{$else}dword{$endif}=0);
const
  magic = 'expand 32-byte k';
begin
  fillchar(state, sizeof(state), 0);

  // magic 16 bytes
  move(magic[1], state.state[0], 16);

  // key 32 bytes; if longer then cut it
  if length(key) > 32 then setlength(key, 32);
  if key <> '' then move(key[1], state.state[4], length(key));

  // counter
  chacha20_set_counter(state, counter);

  // nonce 8 or 12 bytes; if longer then cut it
  {$ifdef COUNTER64}     
  if length(nonce) > 8 then setlength(nonce, 8);
  if nonce <> '' then move(nonce[1], state.state[14], length(nonce));
  {$else} 
  if length(nonce) > 12 then setlength(nonce, 12);
  if nonce <> '' then move(nonce[1], state.state[13], length(nonce));
  {$endif}
end;

procedure chacha20_set_counter(var state: chacha20state; counter: {$ifdef COUNTER64}qword{$else}dword{$endif});
begin
  move(counter, state.state[12], sizeof(counter));
  state.position := 64;
end;

function rotl32(x, n: dword): dword; inline;
begin
  result := (x shl n) or (x shr (32-n));
end;

procedure chacha20_quarterround(p: pdword; a, b, c, d: byte); inline;
begin
  p[a] += p[b]; p[d] := rotl32(p[d] xor p[a], 16);
  p[c] += p[d]; p[b] := rotl32(p[b] xor p[c], 12);
  p[a] += p[b]; p[d] := rotl32(p[d] xor p[a], 8);
  p[c] += p[d]; p[b] := rotl32(p[b] xor p[c], 7);
end;

procedure chacha20_next_block(var state: chacha20state);
var
i: integer;
begin
  // copy state to keystream
  move(state.state, state.keystream, 64);

  // mix the bytes a lot and hope that nobody finds out how to undo it
  for i := 1 to 10 do begin
    chacha20_quarterround(@state.keystream, 0, 4, 8, 12);
    chacha20_quarterround(@state.keystream, 1, 5, 9, 13);
    chacha20_quarterround(@state.keystream, 2, 6, 10, 14);
    chacha20_quarterround(@state.keystream, 3, 7, 11, 15);
    chacha20_quarterround(@state.keystream, 0, 5, 10, 15);
    chacha20_quarterround(@state.keystream, 1, 6, 11, 12);
    chacha20_quarterround(@state.keystream, 2, 7, 8, 13);
    chacha20_quarterround(@state.keystream, 3, 4, 9, 14);
  end;

  // add state dwords to keystream dwords
  for i := 0 to high(state.keystream) do state.keystream[i] += state.state[i];

  // increase counter
  {$ifdef COUNTER64}
  pqword(@state.state[12])^ += 1;
  {$else}
  pdword(@state.state[12])^ += 1;
  {$endif}

  // reset position
  state.position := 0;
end;

procedure chacha20_xor(var state: chacha20state; p: pointer; l: dword);
var
  i: integer;
begin
  for i := 0 to l-1 do begin
    if state.position >= 64 then chacha20_next_block(state);
    pbyte(p+i)^ := pbyte(p+i)^ xor pbyte(@state.keystream[0]+state.position)^;
    inc(state.position);
  end;
end;

end.

