(** This is just some scratch code from trying to figure out the new ML API for
 * Z3 **)

(** Unfortunately Z3 aliases Array and List. Z3s version continue to be
 * accessible using Z3Array and Z3List **)
module Arr = Array;;
module Lst = List;;
open Z3;;
module List = Lst;;
module Array = Arr;;

(** Wrap a func_decl so it is callable. Sadly all the variadic arg methods
 * I could find for OCaml are crazy complicated (don't want to encode church
 * numerals), so still needs list **)
let mk_function (f : FuncDecl.func_decl) = 
    let wrapped_f (vals : Expr.expr list) =
        (FuncDecl.apply f vals) in
    wrapped_f
;;

(* Entry point *)
let _ = (
    (* Make a Z3 context *)
    let context = mk_context([("model", "true"); ("proof", "true")]) in
    (* Define a new Sort *)
    let endpoint = (Sort.mk_uninterpreted_s context "Endpoint") in
    (* Declare variables *)
    let vara = Expr.mk_const_s context "a" endpoint in
    let varb = Expr.mk_const_s context "b" endpoint in
    (* Some definitions to make our lives easier 
     * TODO: Consider putting into an object *)
    let mk_eq = Boolean.mk_eq context in
    let mk_not = Boolean.mk_not context in
    (* Declare a function *)
    let f = (mk_function (FuncDecl.mk_func_decl_s context "f" [endpoint]
                                endpoint)) in
    (* Create a solver *)
    let solver = Solver.mk_solver context None in
        (* Add some constraints *)
        (Solver.add solver [(mk_eq (f [(f [vara])]) 
                                              vara);
                           (mk_eq (f [vara]) varb);
                           (mk_not (mk_eq vara varb))]);
        (* Check satisfiability *)
        let q = (Solver.check solver []) in
        if q != Solver.SATISFIABLE then
            Printf.printf "UNSAT\n"
        else
           Printf.printf "SAT\n";
           let m = (Solver.get_model solver) in 
           match m with
           | None -> Printf.printf ("Could not get model :(\n")
           | Some (m) ->
                Printf.printf "Solver says: %s\n" (Solver.string_of_status q);
                Printf.printf "Model: \n%s\n" (Model.to_string m)
);;
