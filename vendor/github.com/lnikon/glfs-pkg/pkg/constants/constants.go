package constants

import "fmt"

type Algorithm string

const (
	Kruskal = "kruskal"
	Prim    = "mst"
)

func (a *Algorithm) String() string {
	return fmt.Sprintf("%v", *a)
}
