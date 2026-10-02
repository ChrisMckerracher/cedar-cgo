(set-logic QF_BV)
(set-option :incremental true)
(declare-const pointer (_ BitVec 32))
(declare-const length (_ BitVec 32))
(declare-const limit (_ BitVec 32))

(define-fun packed () (_ BitVec 64)
  (bvor (bvshl ((_ zero_extend 32) pointer) (_ bv32 64))
        ((_ zero_extend 32) length)))
(define-fun decoded_pointer () (_ BitVec 32)
  ((_ extract 31 0) (bvlshr packed (_ bv32 64))))
(define-fun decoded_length () (_ BitVec 32)
  ((_ extract 31 0) packed))

(push 1)
(assert (not (and (= decoded_pointer pointer) (= decoded_length length))))
(check-sat)
(pop 1)

(push 1)
(assert (not (= (= packed (_ bv0 64))
                (and (= pointer (_ bv0 32)) (= length (_ bv0 32))))))
(check-sat)
(pop 1)

(define-fun rejected () Bool
  (or (= decoded_pointer (_ bv0 32))
      (= decoded_length (_ bv0 32))
      (bvugt decoded_length limit)))
(define-fun valid_header () Bool
  (and (distinct pointer (_ bv0 32))
       (bvugt length (_ bv0 32))
       (bvule length limit)))

(push 1)
(assert (not (= (not rejected) valid_header)))
(check-sat)
(pop 1)
