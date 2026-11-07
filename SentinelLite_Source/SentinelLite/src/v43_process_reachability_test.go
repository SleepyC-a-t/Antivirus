package main

import (
 "go/ast"
 "go/parser"
 "go/token"
 "os"
 "strconv"
 "strings"
 "testing"
)

// Function-level allowlist: never exempt a whole file for having one explicit
// user action. All passive scan workers and supporting analyzers are checked.
func TestSecurityProcessCreationFunctionAllowlistAndReachability(t *testing.T) {
 allowed:=map[string]bool{
  "runDefender":true, // explicit opt-in Defender engine
  "openLocation":true, // explicit Show in Explorer action
  "openWindowsSecurity":true, // explicit OS security-center action
  "secureLaunchReviewedExecutable":true, // approved, hash-bound Scan & Run
 }
 entrypoints:=[]string{"runHeuristic","inspectFileProtected","inspectFileDetailed","inspectV42PE","pollOnce","watchActiveDirectory"}
 funcs:=map[string]*ast.FuncDecl{}
 files:=map[string]string{}
 nativeProcessProcs:=map[string]string{}
 fset:=token.NewFileSet()
 entries,err:=os.ReadDir(".");if err!=nil{t.Fatal(err)}
 for _,e:=range entries {
  if e.IsDir()||!strings.HasSuffix(e.Name(),".go")||strings.HasSuffix(e.Name(),"_test.go"){continue}
  f,err:=parser.ParseFile(fset,e.Name(),nil,0)
  if err!=nil{t.Fatalf("parse %s: %v",e.Name(),err)}
  for _,decl:=range f.Decls {
   if fn,ok:=decl.(*ast.FuncDecl);ok{
    funcs[fn.Name.Name]=fn
    files[fn.Name.Name]=e.Name()
   }
  }
  // Only process-creation native entrypoints are tracked; WinVerifyTrust,
  // ordinary file/monitor API calls are not process creation.
  ast.Inspect(f,func(n ast.Node)bool{
   call,ok:=n.(*ast.CallExpr);if !ok{return true}
   sel,ok:=call.Fun.(*ast.SelectorExpr);if !ok||sel.Sel.Name!="NewProc"||len(call.Args)!=1{return true}
   s,ok:=call.Args[0].(*ast.BasicLit);if !ok{return true}
   val,_:=strconv.Unquote(s.Value)
   switch strings.ToLower(val) {
   case "createprocessw","createprocessa","winexec","shellexecutew","shellexecuteexw",
    "shellexecutea","shellexecuteexa":
    nativeProcessProcs[val]=e.Name()
   }
   return true
  })
 }
 if len(funcs)<35{t.Fatalf("parsed only %d functions; security graph incomplete",len(funcs))}
 calls:=map[string]map[string]bool{}
 for name,fn:=range funcs{
  calls[name]=map[string]bool{}
  if fn.Body==nil{continue}
  ast.Inspect(fn.Body,func(n ast.Node)bool{
   call,ok:=n.(*ast.CallExpr);if !ok{return true}
   callee:=""
   switch f:=call.Fun.(type) {
   case *ast.Ident: callee=f.Name
   case *ast.SelectorExpr:
    callee=f.Sel.Name
    prefix:=""
    if id,ok:=f.X.(*ast.Ident);ok{prefix=id.Name}
    isDirectProcess:= (prefix=="exec"&&(callee=="Command"||callee=="CommandContext")) ||
      (prefix=="os"&&callee=="StartProcess") ||
      (prefix=="syscall"&&(callee=="StartProcess"||callee=="ForkExec"||callee=="CreateProcess")) ||
      (prefix=="windows"&&callee=="CreateProcess")
    // An exec.Cmd call is not allowed in arbitrary method handlers;
    // 'w.Run' and t.Run are unrelated and intentionally not banned.
    cmdSpawn:=(prefix=="cmd"||prefix=="command")&&(callee=="Run"||callee=="Start"||callee=="Output"||callee=="CombinedOutput")
    if (isDirectProcess||cmdSpawn)&&!allowed[name]{
     t.Errorf("%s:%d: process-launch call %s.%s in non-allowlisted function %s",files[name],fset.Position(call.Pos()).Line,prefix,callee,name)
    }
    if callee=="Call"&&prefix=="shellExecuteExW"&&!allowed[name]{
     t.Errorf("%s:%d: ShellExecuteExW invoked outside function allowlist",files[name],fset.Position(call.Pos()).Line)
    }
   }
   if funcs[callee]!=nil{calls[name][callee]=true}
   return true
  })
 }
 if nativeProcessProcs["ShellExecuteExW"]=="" && nativeProcessProcs["shellexecuteexw"]=="" {
  t.Fatal("expected explicit Windows Shell API declaration vanished; reevaluate audit assumptions")
 }
 for _,root:=range entrypoints{
  if funcs[root]==nil{t.Errorf("missing scan entrypoint %s",root);continue}
  seen:=map[string]bool{}
  queue:=[]string{root}
  for len(queue)>0 {
   name:=queue[0];queue=queue[1:]
   if seen[name]{continue};seen[name]=true
   if allowed[name] {
    t.Errorf("scan entrypoint %s reaches process-launch function %s",root,name)
   }
   for child:=range calls[name]{if !seen[child]{queue=append(queue,child)}}
  }
 }
}
