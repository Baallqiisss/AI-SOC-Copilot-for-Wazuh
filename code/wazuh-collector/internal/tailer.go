package internal

import "github.com/hpcloud/tail"

func NewTail(path string) (*tail.Tail, error) {
	return tail.TailFile(
		path,
		tail.Config{
			Follow: true,
			ReOpen: true,
		},
	)
}
