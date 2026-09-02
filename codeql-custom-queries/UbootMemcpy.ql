/**
 * @name U-Boot unsafe memcpy size
 * @description Finds network-derived values reaching memcpy size
 * @kind problem
 * @problem.severity warning
 * @id cpp/uboot-unsafe-memcpy
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacro().getName().matches("ntoh%") and
      this = mi.getExpr()
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "memcpy" and
      sink.asExpr() = call.getArgument(2)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Network-derived value reaches memcpy size"
