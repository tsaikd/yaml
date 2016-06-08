// Package yaml implements YAML support for the Go language.
//
// Source code and other details for the project are available at GitHub:
//
//   https://github.com/go-yaml/yaml
//
package yaml

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

// MapSlice encodes and decodes as a YAML map.
// The order of keys is preserved when encoding and decoding.
type MapSlice []MapItem

// MapItem is an item in a MapSlice.
type MapItem struct {
	Key, Value interface{}
}

// The Unmarshaler interface may be implemented by types to customize their
// behavior when being unmarshaled from a YAML document. The UnmarshalYAML
// method receives a function that may be called to unmarshal the original
// YAML value into a field or variable. It is safe to call the unmarshal
// function parameter more than once if necessary.
// Generally, the idea is to call the method to unmarshal into a value of
// the correct type, then use this unmarshalled value wherever you need to.
//
// For example:
//
//     type T struct {
//         values map[string]int
//         sum    int
//     }
//
//     func (t *T) UnmarshalYAML(unmarshaler func(interface{}) error) error {
//
//         if err := unmarshaler(t.values); err != nil {
//             return err
//         }
//
//         for _, value := range t.values {
//             t.sum += value
//         }
//
//         return nil
//     }
//
//     var t T
//     yaml.Unmarshal([]byte("T:\n  a: 1\n  b: 2\n  c:3"), &t)
//
//
type Unmarshaler interface {
	UnmarshalYAML(unmarshal func(interface{}) error) error
}

// UnmarshalerTag priority is higher than Unmarshaler
type UnmarshalerTag interface {
	UnmarshalYAMLTag(unmarshal func(v interface{}) error, tag string) error
}

// The Initiator interface my be implemented by types to do things directly
// after the creation of itself by the Decoder. It could be used to
// set customize the instances before the unmarshaler process of the object.
// This is useful for setting of default values.
type Initiator interface {
	BeforeUnmarshalYAML() error
}

// The Marshaler interface may be implemented by types to customize their
// behavior when being marshaled into a YAML document. The returned value
// is marshaled in place of the original value implementing Marshaler.
//
// If an error is returned by MarshalYAML, the marshaling procedure stops
// and returns with the provided error.
type Marshaler interface {
	MarshalYAML() (interface{}, error)
}

// Unmarshal decodes the first document found within the in byte slice
// and assigns decoded values into the out value.
//
// Maps and pointers (to a struct, string, int, etc) are accepted as out
// values. If an internal pointer within a struct is not initialized,
// the yaml package will initialize it if necessary for unmarshalling
// the provided data. The out parameter must not be nil.
//
// The type of the decoded values should be compatible with the respective
// values in out. If one or more values cannot be decoded due to a type
// mismatches, decoding continues partially until the end of the YAML
// content, and a *yaml.TypeError is returned with details for all
// missed values.
//
// Struct fields are only unmarshalled if they are exported (have an
// upper case first letter), and are unmarshalled using the field name
// lowercased as the default key. Custom keys may be defined via the
// "yaml" name in the field tag: the content preceding the first comma
// is used as the key, and the following comma-separated options are
// used to tweak the marshalling process (see Marshal).
// Conflicting names result in a runtime error.
//
// For example:
//
//     type T struct {
//         F int `yaml:"a,omitempty"`
//         B int
//     }
//     var t T
//     yaml.Unmarshal([]byte("a: 1\nb: 2"), &t)
//
//
// Another flag which is supported during umarshaling, but must be used on
// its own, is:
//
//     regexp       Unmarshal all encountered YAML values with keys that
//                  match the regular expression into the tagged field,
//                  which must be a map or a slice of a type that the
//                  YAML value should be unmarshaled into.
//				    [Unmarshaling]
//
// For example:
//
//     type T struct {
//         A int
//         B int
//         Numbers map[string]int `yaml:",regexp:num.*"`
//         Phrases []string `yaml:",regexp:phr.*"`
//     }
//     var t T
//     yaml.Unmarshal([]byte("a: 1\nb: 2\nnum1: 1\nnum2: 50\n" +
//                           "phraseOne: to be or not to be\n" +
//                           "phraseTwo: you can't touch my key!\n" +
//                           "anotherKey: ThisValueWillNotBeUnmarshalled"), &t)
//
// You can also use the regexp flag to get all unmapped values into a map for
// runtime usage:
//
//     type T struct {
//         A int
//         B int
//         EverythingElse map[string]interface{} `yaml:",regexp:.*"`
//     }
//     var t T
//     yaml.Unmarshal([]byte("a: 1\nb: 2\nnum1: 1\nnum2: 50\n" +
//                           "anInteger: 111\n" +
//                           "aFloat: 0.5555\n" +
//                           "anotherKey: WhichIsAstring\n" +
//                           "aSequence: [1, 2, 3]\n" +
//                           "aMapping: {hello: world}"), &t)
//
// The resulting EverythingElse map will contain everything except the values of
// a and b.
//
// See the documentation of Marshal for the format of additional tags and a list
// of supported tag options.
//
func Unmarshal(in []byte, out interface{}) (err error) {
	return unmarshal(in, out, false)
}

// UnmarshalStrict is like Unmarshal except that any fields that are found
// in the data that do not have corresponding struct members, or mapping
// keys that are duplicates, will result in
// an error.
func UnmarshalStrict(in []byte, out interface{}) (err error) {
	return unmarshal(in, out, true)
}

// A Decorder reads and decodes YAML values from an input stream.
type Decoder struct {
	strict bool
	parser *parser
}

// NewDecoder returns a new decoder that reads from r.
//
// The decoder introduces its own buffering and may read
// data from r beyond the YAML values requested.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		parser: newParserFromReader(r),
	}
}

// SetStrict sets whether strict decoding behaviour is enabled when
// decoding items in the data (see UnmarshalStrict). By default, decoding is not strict.
func (dec *Decoder) SetStrict(strict bool) {
	dec.strict = strict
}

// Decode reads the next YAML-encoded value from its input
// and stores it in the value pointed to by v.
//
// See the documentation for Unmarshal for details about the
// conversion of YAML into a Go value.
func (dec *Decoder) Decode(v interface{}) (err error) {
	d := newDecoder(dec.strict)
	defer handleErr(&err)
	node := dec.parser.parse()
	if node == nil {
		return io.EOF
	}
	out := reflect.ValueOf(v)
	if out.Kind() == reflect.Ptr && !out.IsNil() {
		out = out.Elem()
	}
	d.unmarshal(node, out)
	if len(d.terrors) > 0 {
		return &TypeError{d.terrors}
	}
	return nil
}

func unmarshal(in []byte, out interface{}, strict bool) (err error) {
	defer handleErr(&err)
	d := newDecoder(strict)
	p := newParser(in)
	defer p.destroy()
	node := p.parse()
	if node != nil {
		v := reflect.ValueOf(out)
		if v.Kind() == reflect.Ptr && !v.IsNil() {
			v = v.Elem()
		}
		d.unmarshal(node, v)
	}
	if d.terrors != nil && len(d.terrors) > 0 {
		return &TypeError{d.terrors}
	}
	return nil
}

// Marshal serializes the value provided into a YAML document. The structure
// of the generated document will reflect the structure of the value itself.
// Maps and pointers (to struct, string, int, etc) are accepted as the in value.
//
// Struct fields are only marshalled if they are exported (have an upper case
// first letter), and are marshalled using the field name lowercased as the
// default key. Custom keys may be defined via the "yaml" name in the field
// tag: the content preceding the first comma is used as the key, and the
// following comma-separated options are used to tweak the marshalling process.
// Conflicting names result in a runtime error.
//
// The field tag format accepted is:
//
//     `(...) yaml:"[<key>][,<flag1>[,<flag2>]]" (...)`
//
// The following flags are currently supported:
//
//     omitempty    Only include the field if it's not set to the zero
//                  value for the type or to empty slices or maps.
//                  Zero valued structs will be omitted if all their public
//                  fields are zero, unless they implement an IsZero
//                  method (see the IsZeroer interface type), in which
//                  case the field will be included if that method returns true.
//
//     flow         Marshal using a flow style (useful for structs,
//                  sequences and maps).
//
//     inline       Inline the field, which must be a struct or a map,
//                  causing all of its fields or keys to be processed as if
//                  they were part of the outer struct. For maps, keys must
//                  not conflict with the yaml keys of other struct fields.
//
// In addition, if the key is "-", the field is ignored.
//
// For example:
//
//     type T struct {
//         F int `yaml:"a,omitempty"`
//         B int
//     }
//     yaml.Marshal(&T{B: 2}) // Returns "b: 2\n"
//     yaml.Marshal(&T{F: 1}} // Returns "a: 1\nb: 0\n"
//
func Marshal(in interface{}) (out []byte, err error) {
	defer handleErr(&err)
	e := newEncoder()
	defer e.destroy()
	e.marshalDoc("", reflect.ValueOf(in))
	e.finish()
	out = e.out
	return
}

// An Encoder writes YAML values to an output stream.
type Encoder struct {
	encoder *encoder
}

// NewEncoder returns a new encoder that writes to w.
// The Encoder should be closed after use to flush all data
// to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		encoder: newEncoderWithWriter(w),
	}
}

// Encode writes the YAML encoding of v to the stream.
// If multiple items are encoded to the stream, the
// second and subsequent document will be preceded
// with a "---" document separator, but the first will not.
//
// See the documentation for Marshal for details about the conversion of Go
// values to YAML.
func (e *Encoder) Encode(v interface{}) (err error) {
	defer handleErr(&err)
	e.encoder.marshalDoc("", reflect.ValueOf(v))
	return nil
}

// Close closes the encoder by writing any remaining data.
// It does not write a stream terminating string "...".
func (e *Encoder) Close() (err error) {
	defer handleErr(&err)
	e.encoder.finish()
	return nil
}

func handleErr(err *error) {
	if v := recover(); v != nil {
		if e, ok := v.(yamlError); ok {
			*err = e.err
		} else {
			panic(v)
		}
	}
}

type yamlError struct {
	err error
}

func fail(err error) {
	panic(yamlError{err})
}

func failf(format string, args ...interface{}) {
	panic(yamlError{fmt.Errorf("yaml: "+format, args...)})
}

// A TypeError is returned by Unmarshal when one or more fields in
// the YAML document cannot be properly decoded into the requested
// types. When this error is returned, the value is still
// unmarshaled partially.
type TypeError struct {
	Errors []string
}

func (e *TypeError) Error() string {
	return fmt.Sprintf("yaml: unmarshal errors:\n  %s", strings.Join(e.Errors, "\n  "))
}

// --------------------------------------------------------------------------
// Maintain a mapping of keys to structure field indexes

// The code in this section was copied from mgo/bson.

// structInfo holds details for the serialization of fields of
// a given struct.
type structInfo struct {
	Type       reflect.Type
	FieldsMap  map[string]fieldInfo
	FieldsList []fieldInfo

	// InlineMap is the number of the field in the struct that
	// contains an ,inline map, or -1 if there's none.
	InlineMap int

	// This a list of fields with regexps that are tested during unmarshaling,
	// and when matched by a YAML key, will write the value to the designated
	// field value. This is check from top to bottom, the first match wins.
	// Exact key match (using FieldsMap) is checked before the regular
	// expression phase.
	RegexpFieldsList []fieldInfo
}

type fieldInfo struct {
	// YAML key to use for marshaling/unmarshaling of this field
	Key string

	// Index of the field in the struct
	Num int

	// When marshaling, whether to omit this field when it is set to Zero
	OmitEmpty bool

	// Whether to marhsal using the YAML flow style
	Flow bool

	// Id holds the unique field identifier, so we can cheaply
	// check for field duplicates without maintaining an extra map.
	Id int

	// Regular expression that the YAML key must match for unmarshaling into
	// this field
	Regexp *regexp.Regexp

	// Inline holds the field index if the field is part of an inlined struct.
	Inline []int
}

var structMap = make(map[reflect.Type]*structInfo)
var fieldMapMutex sync.RWMutex

func getStructInfo(st reflect.Type) (*structInfo, error) {

	// Try and get the relevant structInfo
	fieldMapMutex.RLock()
	sinfo, found := structMap[st]
	fieldMapMutex.RUnlock()

	// Return it, if found
	if found {
		return sinfo, nil
	}

	// Otherwise, let's create it.
	n := st.NumField()
	fieldsMap := make(map[string]fieldInfo)
	fieldsList := make([]fieldInfo, 0, n)
	regexpFieldsList := make([]fieldInfo, 0)
	inlineMap := -1

	// Go over each field
	for i := 0; i != n; i++ {

		// Get the StructField
		field := st.Field(i)
		if field.PkgPath != "" && !field.Anonymous {
			continue // Private field
		}

		// Create a fieldInfo struct
		info := fieldInfo{Num: i}

		// Try and get the yaml tag from the field
		tag := field.Tag.Get("yaml")

		// An empty tag means a possibly badly formatted tag. We try and act nice
		if tag == "" {

			rawTagString := string(field.Tag)

			if strings.Index(string(field.Tag), ":") < 0 {
				// Handle tags with no yaml: prefix, just use the raw comment
				// tag string
				tag = rawTagString
			} else if strings.HasPrefix(rawTagString, "yaml:") {
				// Handle badly formatted yaml: tags (no quotes, for example)
				failf("Detected badly formatted tag for field %s; missing quotes?\n",
					field.Name)
			}

			// TODO: Consider whether we should be more strict:
			// if tag != "" {
			//     return nil,
			//			  fmt.Errof("Badly formatted yaml tag detected: %s",
			//					    string(field.Tag)
			// }
		}

		// '-' means - skip this field
		if tag == "-" {
			continue
		}

		// First, try and see if we have a regexp flag set - if so, handle it.
		if strings.HasPrefix(tag, ",regexp:") {

			// Store just the pattern
			regex := tag[8:]

			// Compile parses a regular expression. Use it as the key in the
			// hash.
			compiledRegexp := regexp.MustCompile(regex)

			// Verify that the type is indeed a map or a slice
			if field.Type.Kind() != reflect.Map &&
				field.Type.Kind() != reflect.Slice {

				// Die
				failf("field %s.%s has regexp flag set but is not a map or slice",
					st.Name(), field.Name)
			}

			info.Regexp = compiledRegexp
			regexpFieldsList = append(regexpFieldsList, info)
			continue
		}

		// Try and see what flags are set
		inline := false
		if fields := strings.Split(tag, ","); len(fields) > 1 {
			for _, flag := range fields[1:] {
				switch flag {

				// Only include the field if it's not set to the zero
				// value for the type or to empty slices or maps.
				// Does not apply to zero valued structs. [Marshaling]
				case "omitempty":
					info.OmitEmpty = true

				// Marshal using a flow style (useful for structs, sequences and
				// maps.) [Marshaling]
				case "flow":
					info.Flow = true

				// Inline the struct it's applied to, so its fields are processed
				// as if they were part of the outer struct.
				// [Marshaling, Unmarshaling]
				case "inline":
					inline = true

				// Unsupported flag?
				default:
					return nil, errors.New(fmt.Sprintf("Unsupported flag %q in tag %q of type %s", flag, tag, st))
				}
			}
			tag = fields[0]
		}

		// Handle the struct fields as if they were part of the outer struct.
		if inline {
			switch field.Type.Kind() {
			case reflect.Map:
				if inlineMap >= 0 {
					return nil, errors.New("Multiple ,inline maps in struct " + st.String())
				}
				if field.Type.Key() != reflect.TypeOf("") {
					return nil, errors.New("Option ,inline needs a map with string keys in struct " + st.String())
				}
				inlineMap = info.Num
			case reflect.Struct:
				sinfo, err := getStructInfo(field.Type)
				if err != nil {
					return nil, err
				}
				for _, finfo := range sinfo.FieldsList {
					if _, found := fieldsMap[finfo.Key]; found {
						msg := "Duplicated key '" + finfo.Key + "' in struct " + st.String()
						return nil, errors.New(msg)
					}
					if finfo.Inline == nil {
						finfo.Inline = []int{i, finfo.Num}
					} else {
						finfo.Inline = append([]int{i}, finfo.Inline...)
					}
					finfo.Id = len(fieldsList)
					fieldsMap[finfo.Key] = finfo
					fieldsList = append(fieldsList, finfo)
				}
			default:
				//return nil, errors.New("Option ,inline needs a struct value or map field")
				return nil, errors.New("Option ,inline needs a struct value field")
			}
			continue
		}

		if tag != "" {
			// If we have a yaml tag with a custom mapping key, then use it
			info.Key = tag
		} else {
			// Otherwise, use the lower-case name of the field
			info.Key = strings.ToLower(field.Name)
		}

		// Search for duplicate mapping keys, error if found
		if _, found = fieldsMap[info.Key]; found {
			msg := "Duplicated key '" + info.Key + "' in struct " + st.String()
			return nil, errors.New(msg)
		}

		info.Id = len(fieldsList)
		fieldsList = append(fieldsList, info)
		fieldsMap[info.Key] = info
	}

	sinfo = &structInfo{
		Type:             st,
		FieldsMap:        fieldsMap,
		FieldsList:       fieldsList,
		InlineMap:        inlineMap,
		RegexpFieldsList: regexpFieldsList,
	}

	// Set it to the struct map, return it
	fieldMapMutex.Lock()
	structMap[st] = sinfo
	fieldMapMutex.Unlock()

	return sinfo, nil
}

// IsZeroer is used to check whether an object is zero to
// determine whether it should be omitted when marshaling
// with the omitempty flag. One notable implementation
// is time.Time.
type IsZeroer interface {
	IsZero() bool
}

func isZero(v reflect.Value) bool {
	kind := v.Kind()
	if z, ok := v.Interface().(IsZeroer); ok {
		if (kind == reflect.Ptr || kind == reflect.Interface) && v.IsNil() {
			return true
		}
		return z.IsZero()
	}
	switch kind {
	case reflect.String:
		return len(v.String()) == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	case reflect.Slice:
		return v.Len() == 0
	case reflect.Map:
		return v.Len() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Struct:
		vt := v.Type()
		for i := v.NumField() - 1; i >= 0; i-- {
			if vt.Field(i).PkgPath != "" {
				continue // Private field
			}
			if !isZero(v.Field(i)) {
				return false
			}
		}
		return true
	}
	return false
}
