package petstore

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync"
)

// InMemoryServer provides a thread-safe, in-memory implementation of the Petstore API.
type InMemoryServer struct {
	mu    sync.RWMutex
	pets  map[int64]Pet
	order []int64
}

// NewInMemoryServer constructs an empty Petstore API server backed by in-memory storage.
func NewInMemoryServer() *InMemoryServer {
	return &InMemoryServer{
		pets:  make(map[int64]Pet),
		order: make([]int64, 0),
	}
}

// ListPets returns pets up to the provided limit.
func (s *InMemoryServer) ListPets(w http.ResponseWriter, _ *http.Request, params ListPetsParams) {
	limit := int32(0)
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

	s.mu.RLock()
	pets := make([]Pet, 0, len(s.order))
	for _, id := range s.order {
		pets = append(pets, s.pets[id])
	}
	s.mu.RUnlock()

	sort.Slice(pets, func(i, j int) bool {
		return pets[i].Id < pets[j].Id
	})

	result := pets
	if limit > 0 && int(limit) < len(pets) {
		idx := int(limit)
		result = pets[:idx]
		nextID := pets[idx].Id
		w.Header().Set("x-next", "/pets?limit="+strconv.FormatInt(int64(limit), 10)+"&after="+strconv.FormatInt(nextID, 10))
	}

	writeJSON(w, http.StatusOK, result)
}

// CreatePets stores a new pet using the provided payload.
func (s *InMemoryServer) CreatePets(w http.ResponseWriter, r *http.Request) {
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

	s.mu.Lock()
	if _, exists := s.pets[pet.Id]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "pet already exists")
		return
	}
	s.pets[pet.Id] = pet
	s.order = append(s.order, pet.Id)
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
}

// ShowPetById returns details for the requested pet identifier.
func (s *InMemoryServer) ShowPetById(w http.ResponseWriter, _ *http.Request, petId string) {
	id, err := strconv.ParseInt(petId, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "petId must be an integer")
		return
	}

	s.mu.RLock()
	pet, ok := s.pets[id]
	s.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "pet not found")
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

var _ ServerInterface = (*InMemoryServer)(nil)
