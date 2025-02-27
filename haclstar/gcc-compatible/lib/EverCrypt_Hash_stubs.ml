module CI = Cstubs_internals

external _1_EverCrypt_Hash_alg_of_state : _ CI.fatptr -> Unsigned.uint8
  = "_1_EverCrypt_Hash_alg_of_state" 

external _2_EverCrypt_Hash_create_in : Unsigned.uint8 -> CI.voidp
  = "_2_EverCrypt_Hash_create_in" 

external _3_EverCrypt_Hash_create : Unsigned.uint8 -> CI.voidp
  = "_3_EverCrypt_Hash_create" 

external _4_EverCrypt_Hash_init : _ CI.fatptr -> unit
  = "_4_EverCrypt_Hash_init" 

external _5_EverCrypt_Hash_update_multi_256
  : _ CI.fatptr -> bytes CI.ocaml -> Unsigned.uint32 -> unit
  = "_5_EverCrypt_Hash_update_multi_256" 

external _6_EverCrypt_Hash_update2
  : _ CI.fatptr -> Unsigned.uint64 -> bytes CI.ocaml -> unit
  = "_6_EverCrypt_Hash_update2" 

external _7_EverCrypt_Hash_update : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_7_EverCrypt_Hash_update" 

external _8_EverCrypt_Hash_update_multi2
  : _ CI.fatptr -> Unsigned.uint64 -> bytes CI.ocaml -> Unsigned.uint32 ->
    unit = "_8_EverCrypt_Hash_update_multi2" 

external _9_EverCrypt_Hash_update_multi
  : _ CI.fatptr -> bytes CI.ocaml -> Unsigned.uint32 -> unit
  = "_9_EverCrypt_Hash_update_multi" 

external _10_EverCrypt_Hash_update_last_256
  : _ CI.fatptr -> Unsigned.uint64 -> bytes CI.ocaml -> Unsigned.uint32 ->
    unit = "_10_EverCrypt_Hash_update_last_256" 

external _11_EverCrypt_Hash_update_last2
  : _ CI.fatptr -> Unsigned.uint64 -> bytes CI.ocaml -> Unsigned.uint32 ->
    unit = "_11_EverCrypt_Hash_update_last2" 

external _12_EverCrypt_Hash_update_last
  : _ CI.fatptr -> bytes CI.ocaml -> Unsigned.uint64 -> unit
  = "_12_EverCrypt_Hash_update_last" 

external _13_EverCrypt_Hash_finish : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_13_EverCrypt_Hash_finish" 

external _14_EverCrypt_Hash_free : _ CI.fatptr -> unit
  = "_14_EverCrypt_Hash_free" 

external _15_EverCrypt_Hash_copy : _ CI.fatptr -> _ CI.fatptr -> unit
  = "_15_EverCrypt_Hash_copy" 

external _16_EverCrypt_Hash_hash_256
  : bytes CI.ocaml -> Unsigned.uint32 -> bytes CI.ocaml -> unit
  = "_16_EverCrypt_Hash_hash_256" 

external _17_EverCrypt_Hash_hash_224
  : bytes CI.ocaml -> Unsigned.uint32 -> bytes CI.ocaml -> unit
  = "_17_EverCrypt_Hash_hash_224" 

external _18_EverCrypt_Hash_hash
  : Unsigned.uint8 -> bytes CI.ocaml -> bytes CI.ocaml -> Unsigned.uint32 ->
    unit = "_18_EverCrypt_Hash_hash" 

external _19_EverCrypt_Hash_Incremental_hash_len
  : Unsigned.uint8 -> Unsigned.uint32
  = "_19_EverCrypt_Hash_Incremental_hash_len" 

external _20_EverCrypt_Hash_Incremental_block_len
  : Unsigned.uint8 -> Unsigned.uint32
  = "_20_EverCrypt_Hash_Incremental_block_len" 

external _21_EverCrypt_Hash_Incremental_create_in
  : Unsigned.uint8 -> CI.voidp = "_21_EverCrypt_Hash_Incremental_create_in" 

external _22_EverCrypt_Hash_Incremental_init : _ CI.fatptr -> unit
  = "_22_EverCrypt_Hash_Incremental_init" 

external _23_EverCrypt_Hash_Incremental_update
  : _ CI.fatptr -> bytes CI.ocaml -> Unsigned.uint32 -> unit
  = "_23_EverCrypt_Hash_Incremental_update" 

external _24_EverCrypt_Hash_Incremental_finish_md5
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_24_EverCrypt_Hash_Incremental_finish_md5" 

external _25_EverCrypt_Hash_Incremental_finish_sha1
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_25_EverCrypt_Hash_Incremental_finish_sha1" 

external _26_EverCrypt_Hash_Incremental_finish_sha224
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_26_EverCrypt_Hash_Incremental_finish_sha224" 

external _27_EverCrypt_Hash_Incremental_finish_sha256
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_27_EverCrypt_Hash_Incremental_finish_sha256" 

external _28_EverCrypt_Hash_Incremental_finish_sha384
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_28_EverCrypt_Hash_Incremental_finish_sha384" 

external _29_EverCrypt_Hash_Incremental_finish_sha512
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_29_EverCrypt_Hash_Incremental_finish_sha512" 

external _30_EverCrypt_Hash_Incremental_finish_blake2s
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_30_EverCrypt_Hash_Incremental_finish_blake2s" 

external _31_EverCrypt_Hash_Incremental_finish_blake2b
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_31_EverCrypt_Hash_Incremental_finish_blake2b" 

external _32_EverCrypt_Hash_Incremental_alg_of_state
  : _ CI.fatptr -> Unsigned.uint8
  = "_32_EverCrypt_Hash_Incremental_alg_of_state" 

external _33_EverCrypt_Hash_Incremental_finish
  : _ CI.fatptr -> bytes CI.ocaml -> unit
  = "_33_EverCrypt_Hash_Incremental_finish" 

external _34_EverCrypt_Hash_Incremental_free : _ CI.fatptr -> unit
  = "_34_EverCrypt_Hash_Incremental_free" 

type 'a result = 'a
type 'a return = 'a
type 'a fn =
 | Returns  : 'a CI.typ   -> 'a return fn
 | Function : 'a CI.typ * 'b fn  -> ('a -> 'b) fn
let map_result f x = f x
let returning t = Returns t
let (@->) f p = Function (f, p)
let foreign : type a b. string -> (a -> b) fn -> (a -> b) =
  fun name t -> match t, name with
| Function (CI.Pointer _, Returns CI.Void), "EverCrypt_Hash_Incremental_free" ->
  (fun x1 ->
    let CI.CPointer x2 = x1 in _34_EverCrypt_Hash_Incremental_free x2)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish" ->
  (fun x3 x5 ->
    let CI.CPointer x4 = x3 in _33_EverCrypt_Hash_Incremental_finish x4 x5)
| Function
    (CI.Pointer _,
     Returns (CI.View {CI.ty = CI.Primitive CI.Uint8_t; read = x8; _})),
  "EverCrypt_Hash_Incremental_alg_of_state" ->
  (fun x6 ->
    let CI.CPointer x7 = x6 in
    x8 (_32_EverCrypt_Hash_Incremental_alg_of_state x7))
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_blake2b" ->
  (fun x9 x11 ->
    let CI.CPointer x10 = x9 in
    _31_EverCrypt_Hash_Incremental_finish_blake2b x10 x11)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_blake2s" ->
  (fun x12 x14 ->
    let CI.CPointer x13 = x12 in
    _30_EverCrypt_Hash_Incremental_finish_blake2s x13 x14)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_sha512" ->
  (fun x15 x17 ->
    let CI.CPointer x16 = x15 in
    _29_EverCrypt_Hash_Incremental_finish_sha512 x16 x17)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_sha384" ->
  (fun x18 x20 ->
    let CI.CPointer x19 = x18 in
    _28_EverCrypt_Hash_Incremental_finish_sha384 x19 x20)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_sha256" ->
  (fun x21 x23 ->
    let CI.CPointer x22 = x21 in
    _27_EverCrypt_Hash_Incremental_finish_sha256 x22 x23)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_sha224" ->
  (fun x24 x26 ->
    let CI.CPointer x25 = x24 in
    _26_EverCrypt_Hash_Incremental_finish_sha224 x25 x26)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_sha1" ->
  (fun x27 x29 ->
    let CI.CPointer x28 = x27 in
    _25_EverCrypt_Hash_Incremental_finish_sha1 x28 x29)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_Incremental_finish_md5" ->
  (fun x30 x32 ->
    let CI.CPointer x31 = x30 in
    _24_EverCrypt_Hash_Incremental_finish_md5 x31 x32)
| Function
    (CI.Pointer _,
     Function
       (CI.OCaml CI.Bytes,
        Function (CI.Primitive CI.Uint32_t, Returns CI.Void))),
  "EverCrypt_Hash_Incremental_update" ->
  (fun x33 x35 x36 ->
    let CI.CPointer x34 = x33 in
    _23_EverCrypt_Hash_Incremental_update x34 x35 x36)
| Function (CI.Pointer _, Returns CI.Void), "EverCrypt_Hash_Incremental_init" ->
  (fun x37 ->
    let CI.CPointer x38 = x37 in _22_EverCrypt_Hash_Incremental_init x38)
| Function
    (CI.View {CI.ty = CI.Primitive CI.Uint8_t; write = x40; _},
     Returns (CI.Pointer x42)),
  "EverCrypt_Hash_Incremental_create_in" ->
  (fun x39 ->
    let x41 = x40 x39 in
    CI.make_ptr x42 (_21_EverCrypt_Hash_Incremental_create_in x41))
| Function
    (CI.View {CI.ty = CI.Primitive CI.Uint8_t; write = x44; _},
     Returns (CI.Primitive CI.Uint32_t)),
  "EverCrypt_Hash_Incremental_block_len" ->
  (fun x43 ->
    let x45 = x44 x43 in _20_EverCrypt_Hash_Incremental_block_len x45)
| Function
    (CI.View {CI.ty = CI.Primitive CI.Uint8_t; write = x47; _},
     Returns (CI.Primitive CI.Uint32_t)),
  "EverCrypt_Hash_Incremental_hash_len" ->
  (fun x46 ->
    let x48 = x47 x46 in _19_EverCrypt_Hash_Incremental_hash_len x48)
| Function
    (CI.View {CI.ty = CI.Primitive CI.Uint8_t; write = x50; _},
     Function
       (CI.OCaml CI.Bytes,
        Function
          (CI.OCaml CI.Bytes,
           Function (CI.Primitive CI.Uint32_t, Returns CI.Void)))),
  "EverCrypt_Hash_hash" ->
  (fun x49 x52 x53 x54 ->
    let x51 = x50 x49 in _18_EverCrypt_Hash_hash x51 x52 x53 x54)
| Function
    (CI.OCaml CI.Bytes,
     Function
       (CI.Primitive CI.Uint32_t,
        Function (CI.OCaml CI.Bytes, Returns CI.Void))),
  "EverCrypt_Hash_hash_224" -> _17_EverCrypt_Hash_hash_224
| Function
    (CI.OCaml CI.Bytes,
     Function
       (CI.Primitive CI.Uint32_t,
        Function (CI.OCaml CI.Bytes, Returns CI.Void))),
  "EverCrypt_Hash_hash_256" -> _16_EverCrypt_Hash_hash_256
| Function (CI.Pointer _, Function (CI.Pointer _, Returns CI.Void)),
  "EverCrypt_Hash_copy" ->
  (fun x61 x63 ->
    let CI.CPointer x64 = x63 in
    let CI.CPointer x62 = x61 in _15_EverCrypt_Hash_copy x62 x64)
| Function (CI.Pointer _, Returns CI.Void), "EverCrypt_Hash_free" ->
  (fun x65 -> let CI.CPointer x66 = x65 in _14_EverCrypt_Hash_free x66)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_finish" ->
  (fun x67 x69 ->
    let CI.CPointer x68 = x67 in _13_EverCrypt_Hash_finish x68 x69)
| Function
    (CI.Pointer _,
     Function
       (CI.OCaml CI.Bytes,
        Function (CI.Primitive CI.Uint64_t, Returns CI.Void))),
  "EverCrypt_Hash_update_last" ->
  (fun x70 x72 x73 ->
    let CI.CPointer x71 = x70 in _12_EverCrypt_Hash_update_last x71 x72 x73)
| Function
    (CI.Pointer _,
     Function
       (CI.Primitive CI.Uint64_t,
        Function
          (CI.OCaml CI.Bytes,
           Function (CI.Primitive CI.Uint32_t, Returns CI.Void)))),
  "EverCrypt_Hash_update_last2" ->
  (fun x74 x76 x77 x78 ->
    let CI.CPointer x75 = x74 in
    _11_EverCrypt_Hash_update_last2 x75 x76 x77 x78)
| Function
    (CI.Pointer _,
     Function
       (CI.Primitive CI.Uint64_t,
        Function
          (CI.OCaml CI.Bytes,
           Function (CI.Primitive CI.Uint32_t, Returns CI.Void)))),
  "EverCrypt_Hash_update_last_256" ->
  (fun x79 x81 x82 x83 ->
    let CI.CPointer x80 = x79 in
    _10_EverCrypt_Hash_update_last_256 x80 x81 x82 x83)
| Function
    (CI.Pointer _,
     Function
       (CI.OCaml CI.Bytes,
        Function (CI.Primitive CI.Uint32_t, Returns CI.Void))),
  "EverCrypt_Hash_update_multi" ->
  (fun x84 x86 x87 ->
    let CI.CPointer x85 = x84 in _9_EverCrypt_Hash_update_multi x85 x86 x87)
| Function
    (CI.Pointer _,
     Function
       (CI.Primitive CI.Uint64_t,
        Function
          (CI.OCaml CI.Bytes,
           Function (CI.Primitive CI.Uint32_t, Returns CI.Void)))),
  "EverCrypt_Hash_update_multi2" ->
  (fun x88 x90 x91 x92 ->
    let CI.CPointer x89 = x88 in
    _8_EverCrypt_Hash_update_multi2 x89 x90 x91 x92)
| Function (CI.Pointer _, Function (CI.OCaml CI.Bytes, Returns CI.Void)),
  "EverCrypt_Hash_update" ->
  (fun x93 x95 ->
    let CI.CPointer x94 = x93 in _7_EverCrypt_Hash_update x94 x95)
| Function
    (CI.Pointer _,
     Function
       (CI.Primitive CI.Uint64_t,
        Function (CI.OCaml CI.Bytes, Returns CI.Void))),
  "EverCrypt_Hash_update2" ->
  (fun x96 x98 x99 ->
    let CI.CPointer x97 = x96 in _6_EverCrypt_Hash_update2 x97 x98 x99)
| Function
    (CI.Pointer _,
     Function
       (CI.OCaml CI.Bytes,
        Function (CI.Primitive CI.Uint32_t, Returns CI.Void))),
  "EverCrypt_Hash_update_multi_256" ->
  (fun x100 x102 x103 ->
    let CI.CPointer x101 = x100 in
    _5_EverCrypt_Hash_update_multi_256 x101 x102 x103)
| Function (CI.Pointer _, Returns CI.Void), "EverCrypt_Hash_init" ->
  (fun x104 -> let CI.CPointer x105 = x104 in _4_EverCrypt_Hash_init x105)
| Function
    (CI.View {CI.ty = CI.Primitive CI.Uint8_t; write = x107; _},
     Returns (CI.Pointer x109)),
  "EverCrypt_Hash_create" ->
  (fun x106 ->
    let x108 = x107 x106 in CI.make_ptr x109 (_3_EverCrypt_Hash_create x108))
| Function
    (CI.View {CI.ty = CI.Primitive CI.Uint8_t; write = x111; _},
     Returns (CI.Pointer x113)),
  "EverCrypt_Hash_create_in" ->
  (fun x110 ->
    let x112 = x111 x110 in
    CI.make_ptr x113 (_2_EverCrypt_Hash_create_in x112))
| Function
    (CI.Pointer _,
     Returns (CI.View {CI.ty = CI.Primitive CI.Uint8_t; read = x116; _})),
  "EverCrypt_Hash_alg_of_state" ->
  (fun x114 ->
    let CI.CPointer x115 = x114 in x116 (_1_EverCrypt_Hash_alg_of_state x115))
| _, s ->  Printf.ksprintf failwith "No match for %s" s


let foreign_value : type a. string -> a Ctypes.typ -> a Ctypes.ptr =
  fun name t -> match t, name with
| _, s ->  Printf.ksprintf failwith "No match for %s" s
