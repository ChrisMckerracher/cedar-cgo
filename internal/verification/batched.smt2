; Models charge, calls++, int(n), and int32(len(body)) in cedar/batched.go.
; Native int may be 32 or 64 bits; sizes are nonnegative and capped by their source guards.
; Excludes JSON correctness, guest memory, callbacks, Cedar semantics, and control-flow verification.
(set-logic QF_BV)
(set-option :incremental true)

(declare-const host_max (_ BitVec 64))
(assert (or (= host_max (_ bv2147483647 64))
            (= host_max (_ bv9223372036854775807 64))))
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

; The unsigned batch check precedes converting the guest's request size to int.
(declare-const request_length (_ BitVec 32))
(push 1)
(assert (bvule ((_ zero_extend 32) request_length) max_batch))
(check-sat)
(push 1)
(assert (not (and
  (= ((_ sign_extend 32) request_length) ((_ zero_extend 32) request_length))
  (bvule ((_ zero_extend 32) request_length) host_max))))
(check-sat)
(pop 1)
(pop 1)

; A successful JSON object is nonempty; JSON serialization itself is outside this model.
(declare-const result_length (_ BitVec 64))
(define-fun returned_length () (_ BitVec 32) ((_ extract 31 0) result_length))
(push 1)
(assert (and (bvugt result_length (_ bv0 64)) (bvule result_length max_batch)))
(check-sat)
(push 1)
(assert (not (and
  (= ((_ sign_extend 32) returned_length) result_length)
  (bvsgt returned_length (_ bv0 32))
  (distinct returned_length #xffffffff))))
(check-sat)
(pop 1)
(pop 1)
