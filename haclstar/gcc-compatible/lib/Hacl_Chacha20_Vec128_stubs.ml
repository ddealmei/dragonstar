module CI = Cstubs_internals

external _1_Hacl_Chacha20_Vec128_chacha20_encrypt_128
  : Unsigned.uint32 -> bytes CI.ocaml -> bytes CI.ocaml -> bytes CI.ocaml ->
    bytes CI.ocaml -> Unsigned.uint32 -> unit
  =
  "_1_Hacl_Chacha20_Vec128_chacha20_encrypt_128_byte6" "_1_Hacl_Chacha20_Vec128_chacha20_encrypt_128"
  

external _2_Hacl_Chacha20_Vec128_chacha20_decrypt_128
  : Unsigned.uint32 -> bytes CI.ocaml -> bytes CI.ocaml -> bytes CI.ocaml ->
    bytes CI.ocaml -> Unsigned.uint32 -> unit
  =
  "_2_Hacl_Chacha20_Vec128_chacha20_decrypt_128_byte6" "_2_Hacl_Chacha20_Vec128_chacha20_decrypt_128"
  

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
| Function
    (CI.Primitive CI.Uint32_t,
     Function
       (CI.OCaml CI.Bytes,
        Function
          (CI.OCaml CI.Bytes,
           Function
             (CI.OCaml CI.Bytes,
              Function
                (CI.OCaml CI.Bytes,
                 Function (CI.Primitive CI.Uint32_t, Returns CI.Void)))))),
  "Hacl_Chacha20_Vec128_chacha20_decrypt_128" ->
  _2_Hacl_Chacha20_Vec128_chacha20_decrypt_128
| Function
    (CI.Primitive CI.Uint32_t,
     Function
       (CI.OCaml CI.Bytes,
        Function
          (CI.OCaml CI.Bytes,
           Function
             (CI.OCaml CI.Bytes,
              Function
                (CI.OCaml CI.Bytes,
                 Function (CI.Primitive CI.Uint32_t, Returns CI.Void)))))),
  "Hacl_Chacha20_Vec128_chacha20_encrypt_128" ->
  _1_Hacl_Chacha20_Vec128_chacha20_encrypt_128
| _, s ->  Printf.ksprintf failwith "No match for %s" s


let foreign_value : type a. string -> a Ctypes.typ -> a Ctypes.ptr =
  fun name t -> match t, name with
| _, s ->  Printf.ksprintf failwith "No match for %s" s
