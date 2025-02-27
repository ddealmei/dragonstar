module CI = Cstubs_internals

external _1_Hacl_Poly1305_128_blocklen : unit -> CI.voidp
  = "_1_Hacl_Poly1305_128_blocklen" 

external _2_Hacl_Poly1305_128_poly1305_mac
  : bytes CI.ocaml -> Unsigned.uint32 -> bytes CI.ocaml -> bytes CI.ocaml ->
    unit = "_2_Hacl_Poly1305_128_poly1305_mac" 

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
    (CI.OCaml CI.Bytes,
     Function
       (CI.Primitive CI.Uint32_t,
        Function
          (CI.OCaml CI.Bytes, Function (CI.OCaml CI.Bytes, Returns CI.Void)))),
  "Hacl_Poly1305_128_poly1305_mac" -> _2_Hacl_Poly1305_128_poly1305_mac
| _, s ->  Printf.ksprintf failwith "No match for %s" s


let foreign_value : type a. string -> a Ctypes.typ -> a Ctypes.ptr =
  fun name t -> match t, name with
| (CI.Primitive CI.Uint32_t as x5), "Hacl_Poly1305_128_blocklen" ->
  (CI.make_ptr x5 (_1_Hacl_Poly1305_128_blocklen ()))
| _, s ->  Printf.ksprintf failwith "No match for %s" s
