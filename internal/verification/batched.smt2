; Models charge, calls++, and native callback lengths in cedar/authorization/batched.
; Supported native targets use 64-bit int; sizes are nonnegative and capped by their source guards.
; Excludes JSON correctness, pointers, ownership, Cedar semantics, and control-flow verification.
; UTF-8 guards only reject input; accepted lengths and their bounds remain unchanged.
(set-logic QF_BV)
(set-option :incremental true)

(declare-const host_max (_ BitVec 64))
(assert (= host_max (_ bv9223372036854775807 64)))
(declare-const max_batch (_ BitVec 64))
(assert (and (bvugt max_batch (_ bv0 64))
             (bvule max_batch (_ bv67108864 64))))

; charge receives len(body) or a uint32 request size after the batch bound.
(declare-const remaining (_ BitVec 64))
(declare-const charge (_ BitVec 64))
(define-fun accepted_charge () Bool
  (not (or (bvugt charge max_batch) (bvugt charge remaining))))
(define-fun next_remaining () (_ BitVec 64) (bvsub remaining charge))
(push 1)
(assert (bvule remaining host_max))
(assert accepted_charge)
(check-sat)
(push 1)
(assert (not (and (bvule next_remaining remaining)
                  (bvule next_remaining host_max))))
(check-sat)
(pop 1)
; Widening the conservation equation prevents modular arithmetic hiding underflow.
(push 1)
(assert (not (= (bvadd ((_ zero_extend 1) charge)
                      ((_ zero_extend 1) next_remaining))
                ((_ zero_extend 1) remaining))))
(check-sat)
(pop 1)
(pop 1)

; The source rejects calls >= maxCalls before incrementing the uint32 counter.
(declare-const calls (_ BitVec 32))
(declare-const max_calls (_ BitVec 32))
(define-fun next_calls () (_ BitVec 32) (bvadd calls (_ bv1 32)))
(push 1)
(assert (bvult calls max_calls))
(check-sat)
(push 1)
(assert (not (and (bvugt next_calls calls) (bvule next_calls max_calls))))
(check-sat)
(pop 1)
(pop 1)

; The batch check bounds a borrowed native request length.
(declare-const request_length (_ BitVec 64))
(push 1)
(assert (bvule request_length max_batch))
(check-sat)
(push 1)
(assert (not (and
  (= request_length request_length)
  (bvule request_length host_max))))
(check-sat)
(pop 1)
(pop 1)

; A successful JSON object is nonempty; JSON serialization itself is outside this model.
(declare-const result_length (_ BitVec 64))
(define-fun returned_length () (_ BitVec 64) result_length)
(push 1)
(assert (and (bvugt result_length (_ bv0 64)) (bvule result_length max_batch)))
(check-sat)
(push 1)
(assert (not (and
  (= returned_length result_length)
  (bvsgt returned_length (_ bv0 64))
  (distinct returned_length #xffffffffffffffff))))
(check-sat)
(pop 1)
(pop 1)
