open! Core

module Source = struct
  type t =
    | Self
    | Unsafe_inline
    | Unsafe_eval
    | Strict_dynamic
    | Report_sample
    | Inline_content of string
    | Host_or_scheme of string
  [@@deriving compare, sexp_of]

  let to_string = function
    | Self -> "'self'"
    | Unsafe_inline -> "'unsafe-inline'"
    | Unsafe_eval -> "'unsafe-eval'"
    | Strict_dynamic -> "'strict-dynamic'"
    | Report_sample -> "'report-sample'"
    | Inline_content content ->
      let hash =
        Base64.encode_string (Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) content)
      in
      [%string "'sha256-%{hash}'"]
    | Host_or_scheme s -> s
  ;;

  let list_to_string = function
    | [] -> "'none'"
    | ts -> List.map ts ~f:to_string |> String.concat ~sep:" "
  ;;
end

module Fetch_type = struct
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

  let to_string = function
    | Connect -> "connect-src"
    | Default -> "default-src"
    | Font -> "font-src"
    | Frame -> "frame-src"
    | Img -> "img-src"
    | Manifest -> "manifest-src"
    | Media -> "media-src"
    | Object -> "object-src"
    | Prefetch -> "prefetch-src"
    | Script -> "script-src"
    | Style -> "style-src"
    | Worker -> "worker-src"
  ;;
end

type t =
  { report_uri : string option
  ; fetch_directives : (Fetch_type.t, Source.t list) List.Assoc.t
  ; base_uri : Source.t list option
  ; form_action : Source.t list option
  ; frame_ancestors : Source.t list option
  ; insecure_requests : [ `Block | `Upgrade | `Allow ]
  }
[@@deriving sexp_of]

let create
  ?report_uri
  ?base_uri
  ?form_action
  ?frame_ancestors
  ~insecure_requests
  fetch_directives
  =
  { report_uri
  ; fetch_directives =
      List.Assoc.map fetch_directives ~f:(List.dedup_and_sort ~compare:Source.compare)
  ; base_uri
  ; form_action
  ; frame_ancestors
  ; insecure_requests
  }
;;

let sources_based_directive_to_string name sources =
  name ^ " " ^ Source.list_to_string sources
;;

let sources_based_directive_to_string' name sources =
  Option.map sources ~f:(sources_based_directive_to_string name)
;;

let fetch_directive_to_string (type_, sources) =
  sources_based_directive_to_string (Fetch_type.to_string type_) sources
;;

let insecure_requests_to_string = function
  | `Allow -> None
  | `Block -> Some "block-all-mixed-content"
  | `Upgrade -> Some "upgrade-insecure-requests"
;;

let to_string
  { report_uri
  ; fetch_directives
  ; base_uri
  ; form_action
  ; frame_ancestors
  ; insecure_requests
  }
  =
  [ Option.map report_uri ~f:(fun uri -> "report-uri " ^ uri) |> Option.to_list
  ; sources_based_directive_to_string' "base-uri" base_uri |> Option.to_list
  ; sources_based_directive_to_string' "form-action" form_action |> Option.to_list
  ; sources_based_directive_to_string' "frame-ancestors" frame_ancestors |> Option.to_list
  ; insecure_requests_to_string insecure_requests |> Option.to_list
  ; List.map fetch_directives ~f:fetch_directive_to_string
  ]
  |> List.concat
  |> List.map ~f:(fun dir -> dir ^ ";")
  |> String.concat ~sep:" "
;;

let header_name = "Content-Security-Policy"
let header_name_report_only = "Content-Security-Policy-Report-Only"
