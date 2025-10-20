package strategy

import (
	"context"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

// ItemSourceStrategy defines the contract for item data source operations
//
// This interface abstracts item data source operations, providing a clean contract
// for implementations that handle different item data sources and management strategies.
// It supports various item sources and inventory systems through the strategy pattern.
//
// Implementations should handle:
//   - Item retrieval from different sources (databases, APIs, files, etc.)
//   - Point-of-sale specific item queries
//   - Stock level management and updates
//   - Data synchronization and caching
//
type ItemSourceStrategy interface {
	// GetItemByID retrieves a specific item by its unique identifier
	//
	// This method fetches a single item from the data source using its unique ID.
	// It should handle:
	//   - Item lookup and retrieval
	//   - Data validation and error handling
	//   - Caching strategies if applicable
	//   - Source-specific query optimization
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - itemID: The unique identifier of the item to retrieve
	//
	// Returns:
	//   - *itemDomain.Item: The retrieved item, or nil if not found
	//   - error: Any error encountered during retrieval (not found, network issues, etc.)
	GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error)

	// GetItemsByPointOfSale retrieves all items associated with a specific point of sale
	//
	// This method fetches all items that belong to or are available at a particular
	// point of sale location. It should handle:
	//   - Point-of-sale specific item filtering
	//   - Bulk item retrieval optimization
	//   - Data pagination if needed
	//   - Location-based inventory management
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - posID: The unique identifier of the point of sale
	//
	// Returns:
	//   - []itemDomain.Item: Collection of items available at the specified point of sale
	//   - error: Any error encountered during retrieval
	GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error)

	// UpdateItemStock updates the stock level for a specific item
	//
	// This method modifies the stock quantity for an item in the data source.
	// It should handle:
	//   - Stock level validation and constraints
	//   - Atomic updates to prevent race conditions
	//   - Inventory tracking and audit logging
	//   - Low stock notifications if applicable
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - itemID: The unique identifier of the item to update
	//   - newStock: The new stock quantity to set
	//
	// Returns:
	//   - error: Any error encountered during the update operation
	UpdateItemStock(ctx context.Context, itemID string, newStock int) error

	// GetSourceType returns the type identifier for this item source strategy
	//
	// This method provides a unique identifier for the specific item source
	// implementation. This identifier is used for:
	//   - Strategy selection and routing
	//   - Logging and debugging purposes
	//   - Configuration and feature flagging
	//   - Monitoring and metrics collection
	//
	// Returns:
	//   - string: A unique identifier for this source type (e.g., "database", "api", "file")
	GetSourceType() string
}
