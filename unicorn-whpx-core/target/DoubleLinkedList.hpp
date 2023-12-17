#ifndef DOUBLELINKEDLIST_HPP
#define DOUBLELINKEDLIST_HPP

struct _DLIST_ENTRY {
    struct _DLIST_ENTRY* Prev;
    struct _DLIST_ENTRY* Next;
};

typedef struct _DLIST_ENTRY DLIST_ENTRY;
typedef struct _DLIST_ENTRY* PDLIST_ENTRY;

struct _DLIST_HEADER {
    struct _DLIST_ENTRY* Head;
    struct _DLIST_ENTRY* Tail;
    size_t Count;
};

typedef struct _DLIST_HEADER DLIST_HEADER;
typedef struct _DLIST_HEADER* PDLIST_HEADER;

// Initialize a Doubly Linked List header
//
void InitializeDListHeader( PDLIST_HEADER Header );

// Flush the content of a double linked list
//
void FlushDList( PDLIST_HEADER Header );

// Get the head (first element) of a double linked list
//
PDLIST_ENTRY GetDListHead( PDLIST_HEADER Header );

// Get the tail (last element) of a double linked list
//
PDLIST_ENTRY GetDListTail( PDLIST_HEADER Header );

// Get the number of elements
//
size_t GetDListCount( PDLIST_HEADER Header );

// Push an element in front (start) of the list
//
PDLIST_ENTRY PushFrontDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Entry );

// Push an element in back (end) of the list
//
PDLIST_ENTRY PushBackDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Entry );

// Insert an element before the specified item
//
PDLIST_ENTRY InsertBeforeDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item, PDLIST_ENTRY Entry );

// Insert an element after the specified item
//
PDLIST_ENTRY InsertAfterDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item, PDLIST_ENTRY Entry );

// Remove an element from the head (start) of the list
//
PDLIST_ENTRY PopFrontDListEntry( PDLIST_HEADER Header );

// Remove an element from the tail (end) of the list
//
PDLIST_ENTRY PopBackDListEntry( PDLIST_HEADER Header );

// Remove an element before the specified item
//
PDLIST_ENTRY RemoveBeforeDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item );

// Remove an element after the specified item
//
PDLIST_ENTRY RemoveAfterDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item );

// Signature of a "find" predicate
//
typedef bool ( *PDLIST_FINDPREDICATE )( const PDLIST_ENTRY Entry );

// Find the entry matching the predicate
//
PDLIST_ENTRY FindDListEntry( PDLIST_HEADER Header, PDLIST_FINDPREDICATE Predicate );

// Signature of the list entry comparator
//
typedef int ( *PDLIST_COMPARATOR )( const PDLIST_ENTRY* a, const PDLIST_ENTRY* b );

// Sort the list following the compartor policy
//
void SortDListBy( PDLIST_HEADER Header, PDLIST_COMPARATOR Comparator );

#endif // !DOUBLELINKEDLIST_HPP