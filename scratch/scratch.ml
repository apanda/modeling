(** This is just some scratch code from trying to figure out the new ML API for
 * Z3 **)

(** Unfortunately Z3 aliases Array and List. Z3s version continue to be
 * accessible using Z3Array and Z3List **)
module Arr = Array;;
module Lst = List;;
open Z3;;
module List = Lst;;
module Array = Arr;;

(* No other functions in this file, just a main function that does what we
 * need *)
let _ = (
    (* Make a Z3 context *)
    let context = mk_context([("model", "true"); ("proof", "true")]) in
    (* Define a new Sort *)
    let endpoint = (Sort.mk_uninterpreted_s context "Endpoint") in
    (* Declare variables *)
    let vara = Expr.mk_const_s context "a" endpoint in
    let varb = Expr.mk_const_s context "b" endpoint in
    (* Declare a function *)
    let f = (FuncDecl.mk_func_decl_s context "f" [endpoint] endpoint) in
    (* Create a solver *)
    let solver = Solver.mk_solver context None in
        (* Add some constraints *)
        (Solver.add solver [(Boolean.mk_eq context (FuncDecl.apply f
                                          [(FuncDecl.apply f [vara])]) 
                                                    vara);
                           (Boolean.mk_eq context (FuncDecl.apply f [vara]) 
                                                    varb);
                           (Boolean.mk_not context (Boolean.mk_eq context vara varb))]);
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
