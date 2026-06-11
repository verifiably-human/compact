#!chezscheme

;;; This file is part of Compact.
;;; Copyright (C) 2026 contributors to Minokawa Compact
;;; SPDX-License-Identifier: Apache-2.0
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; You may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;; 	http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;;; Security analysis observables.
;;;
;;; This library does not perform any analysis of its own. The real
;;; witness data-flow analysis lives in `track-witness-data`
;;; (analysis-passes.ss). That pass populates the parameters defined
;;; here with JSON-shaped findings; save-security-analysis serialises
;;; them.
;;;
;;; The parameters hold one of:
;;;   #f               -- analysis has not run in this dynamic extent
;;;   '#()             -- analysis ran and found nothing
;;;   a vector of records -- analysis ran and produced results
;;;
;;; Each leak record:
;;;   (("location" . src-loc)
;;;    ("what" . string)
;;;    ("witnesses" . #(witness-record ...)))
;;;
;;; Each disclosure record:
;;;   (("location" . src-loc)
;;;    ("witnesses" . #(witness-record ...)))
;;;
;;; Each witness-record:
;;;   (("origin" . origin-record)
;;;    ("paths" . #(path-record ...)))
;;;
;;; origin-record (one of):
;;;   (("kind" . "witness-return-value") ("function" . str) ("location" . src-loc))
;;;   (("kind" . "constructor-argument") ("argument" . str) ("location" . src-loc))
;;;   (("kind" . "circuit-argument") ("function" . str) ("argument" . str) ("location" . src-loc))
;;;
;;; path-record:
;;;   (("points" . #(point ...))
;;;    ("final_exposure" . string))
;;;
;;; point:
;;;   (("description" . string)
;;;    ("location" . src-loc)
;;;    ("exposure" . string-or-null))
;;;
;;; src-loc:
;;;   (("file" . string) ("line" . int) ("column" . int))
;;;   or, when line/column unavailable,
;;;   (("file" . string) ("character" . int))

(library (security-analysis-passes)
  (export security-leaks-json
          security-disclosures-json
          source-object->json)
  (import (except (chezscheme) errorf))

  (define security-leaks-json (make-parameter #f))
  (define security-disclosures-json (make-parameter #f))

  ;; Convert a Chez source-object to a JSON-shape location.
  ;; Tries to resolve line/column; falls back to character offset.
  (define (source-object->json src)
    (let ([sfd (source-object-sfd src)]
          [bfp (source-object-bfp src)])
      (let ([path (source-file-descriptor-path sfd)])
        (call-with-values
          (lambda () (locate-source-object-source src #t #f))
          (case-lambda
            [() `(("file" . ,path) ("character" . ,bfp))]
            [(_resolved-path line col)
             `(("file" . ,path) ("line" . ,line) ("column" . ,col))])))))
)
