package petstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// Server implements the Petstore API backed by a PetRepository.
type Server struct {
	repo PetRepository
}

// NewServer constructs a server using the supplied repository.
func NewServer(repo PetRepository) *Server {
	return &Server{repo: repo}
}

// ListPets returns pets up to the provided limit.
func (s *Server) ListPets(w http.ResponseWriter, r *http.Request, params ListPetsParams) {
	var limit int32
	if params.Limit != nil {
		limit = *params.Limit
		if limit < 0 {
			writeError(w, http.StatusBadRequest, "limit must be non-negative")
			return
		}
		if limit > 100 {
			limit = 100
		}
	}

	fetchLimit := limit
	if limit > 0 {
		fetchLimit = limit + 1
	}

	pets, err := s.repo.ListPets(r.Context(), fetchLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list pets")
		return
	}

	result := pets
	if limit > 0 && len(pets) > int(limit) {
		result = pets[:limit]
		nextID := pets[limit].Id
		w.Header().Set("x-next", fmt.Sprintf("/pets?limit=%d&after=%d", limit, nextID))
	}

	writeJSON(w, http.StatusOK, result)
}

// CreatePets stores a new pet using the provided payload.
func (s *Server) CreatePets(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var pet Pet
	if err := json.NewDecoder(r.Body).Decode(&pet); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := validatePet(pet); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.CreatePet(r.Context(), pet); err != nil {
		if errors.Is(err, ErrPetExists) {
			writeError(w, http.StatusConflict, "pet already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create pet")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// ShowPetById returns details for the requested pet identifier.
func (s *Server) ShowPetById(w http.ResponseWriter, r *http.Request, petId string) {
	id, err := strconv.ParseInt(petId, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "petId must be an integer")
		return
	}

	pet, err := s.repo.GetPet(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrPetNotFound) {
			writeError(w, http.StatusNotFound, "pet not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch pet")
		return
	}

	writeJSON(w, http.StatusOK, pet)
}

func validatePet(pet Pet) error {
	if pet.Id == 0 {
		return errors.New("id is required")
	}
	if pet.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, Error{Code: int32(status), Message: message})
}

var _ ServerInterface = (*Server)(nil)
