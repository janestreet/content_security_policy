open! Core

module Hash_algorithm : sig
  type t =
    | Sha256
    | Sha384
    | Sha512
  [@@deriving compare, sexp_of]
end

module Source : sig
  type t =
    | Self
    | Unsafe_inline
    | Unsafe_eval
    | Strict_dynamic
    | Report_sample
    | Nonce of string
    | Hash of
        { algorithm : Hash_algorithm.t
        ; value : string
        }
    | Host_or_scheme of string
  [@@deriving compare, sexp_of]
end

module Fetch_type : sig
  type t =
    | Connect
    | Default
    | Font
    | Frame
    | Img
    | Manifest
    | Media
    | Object
    | Prefetch
    | Script
    | Style
    | Worker
  [@@deriving compare, sexp_of]
end

type t [@@deriving sexp_of]

(** Create a Content Security Policy, which can be enforced by using it as a response
    header. The default behavior for all of the optional parameters is to allow everything
    (which matches the behavior if you have no CSP). Thus a no-op policy can be created
    by:

    {[
      create ~insecure_requests:`Allow []
    ]}

    While a maximally restrictive policy (except for the [sandbox] directive; see below)
    can be created by:

    {[
      create
        ~base_uri:[]
        ~form_action:[]
        ~frame_ancestors:[]
        ~require_sri_for_script:()
        ~require_sri_for_style:()
        ~insecure_requests:`Block
        [Default, [None]]
    ]}

    The [sandbox] directive isn't exposed because we don't understand how to use it
    properly. Please contact the library owners if this would be useful to you. *)
val create
  :  ?report_uri:string
  -> ?base_uri:Source.t list
  -> ?form_action:Source.t list
  -> ?frame_ancestors:Source.t list
  -> ?plugin_types:string list
  -> ?require_sri_for_script:unit
  -> ?require_sri_for_style:unit
  -> insecure_requests:[ `Block | `Upgrade | `Allow ]
  -> (Fetch_type.t, Source.t list) List.Assoc.t
  -> t

val to_string : t -> string
val header_name : string
val header_name_report_only : string
