package utils

import (
	"encoding/json"
	"net/http"

	"github.com/golang-trading-signal/libs/errs"
)

func WriteResponse(w http.ResponseWriter, code int, data interface{}, err *errs.AppError) {
	w.Header().Add("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(err.Code)
		if err := json.NewEncoder(w).Encode(err.AsMessage()); err != nil {
			panic(err)
		}
	} else {
		w.WriteHeader(code)
		if err := json.NewEncoder(w).Encode(data); err != nil {
			panic(err)
		}
	}
}
