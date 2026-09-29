// Package pgutil converts between plain Go types and the pgtype wrappers
// sqlc generates for nullable Postgres columns, so services and handlers
// don't each reimplement the conversion.
package pgutil

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Timestamptz converts t to a valid pgtype.Timestamptz.
func Timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// TimePtr converts a pgtype.Timestamptz to *time.Time, nil if not valid.
func TimePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// TimestamptzFromPtr is Timestamptz's write-side counterpart: *time.Time
// to a pgtype.Timestamptz, invalid (SQL NULL) if t is nil.
func TimestamptzFromPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// Text converts s to a valid pgtype.Text.
func Text(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

// TextOrEmpty converts a pgtype.Text to a plain string, "" if not valid.
func TextOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// StringPtr converts a pgtype.Text to *string, nil if not valid.
func StringPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

// TextFromPtr is StringPtr's write-side counterpart: *string to a
// pgtype.Text, invalid (SQL NULL) if s is nil.
func TextFromPtr(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// NullUUID converts *uuid.UUID to a pgtype.UUID, invalid (SQL NULL) if id
// is nil.
func NullUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// UUID converts a pgtype.UUID to uuid.UUID; the zero UUID if not valid.
func UUID(id pgtype.UUID) uuid.UUID {
	return uuid.UUID(id.Bytes)
}

// UUIDPtr converts a pgtype.UUID to *string (its canonical string form),
// nil if not valid -- the pgtype.UUID counterpart to StringPtr, for an
// optional foreign key like group_id that a response field renders as
// `*string`/`omitempty` rather than a bare uuid.UUID.
func UUIDPtr(id pgtype.UUID) *string {
	if !id.Valid {
		return nil
	}
	s := UUID(id).String()
	return &s
}

// Int4Ptr converts a pgtype.Int4 to *int32, nil if not valid.
func Int4Ptr(v pgtype.Int4) *int32 {
	if !v.Valid {
		return nil
	}
	return &v.Int32
}

// Int8Ptr converts a pgtype.Int8 to *int64, nil if not valid.
func Int8Ptr(v pgtype.Int8) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}

// Int4 converts v to a valid pgtype.Int4.
func Int4(v int32) pgtype.Int4 {
	return pgtype.Int4{Int32: v, Valid: true}
}

// Int8 converts v to a valid pgtype.Int8.
func Int8(v int64) pgtype.Int8 {
	return pgtype.Int8{Int64: v, Valid: true}
}

// Bool converts v to a valid pgtype.Bool.
func Bool(v bool) pgtype.Bool {
	return pgtype.Bool{Bool: v, Valid: true}
}

// Float8 converts v to a valid pgtype.Float8.
func Float8(v float64) pgtype.Float8 {
	return pgtype.Float8{Float64: v, Valid: true}
}

// Float8Ptr converts a pgtype.Float8 to *float64, nil if not valid.
func Float8Ptr(v pgtype.Float8) *float64 {
	if !v.Valid {
		return nil
	}
	return &v.Float64
}

// BoolPtr converts a pgtype.Bool to *bool, nil if not valid.
func BoolPtr(v pgtype.Bool) *bool {
	if !v.Valid {
		return nil
	}
	return &v.Bool
}

// BoolFromPtr converts *bool to a pgtype.Bool, invalid (SQL NULL) if v is
// nil -- the write-side counterpart to BoolPtr, for a metric field that
// may genuinely be "not collected" rather than a fabricated false.
func BoolFromPtr(v *bool) pgtype.Bool {
	if v == nil {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: *v, Valid: true}
}

// Int4FromPtr is Int4Ptr's write-side counterpart: *int32 to a
// pgtype.Int4, invalid (SQL NULL) if v is nil.
func Int4FromPtr(v *int32) pgtype.Int4 {
	if v == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *v, Valid: true}
}

// Int8FromPtr is Int8Ptr's write-side counterpart: *int64 to a
// pgtype.Int8, invalid (SQL NULL) if v is nil.
func Int8FromPtr(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *v, Valid: true}
}

// Float8FromPtr is Float8Ptr's write-side counterpart: *float64 to a
// pgtype.Float8, invalid (SQL NULL) if v is nil.
func Float8FromPtr(v *float64) pgtype.Float8 {
	if v == nil {
		return pgtype.Float8{}
	}
	return pgtype.Float8{Float64: *v, Valid: true}
}
