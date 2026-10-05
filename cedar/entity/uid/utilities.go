package uid

import "context"

type Renderer interface {
	RenderUID(context.Context, EntityUID) (string, error)
}

func (u EntityUID) CedarText(ctx context.Context, client Renderer) (string, error) {
	return client.RenderUID(ctx, u)
}
