#include "DoubleLinkedList.hpp"

#include <stddef.h>
#include <stdlib.h>

// Initialize a Doubly Linked List header
//
void InitializeDListHeader( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return;

    Header->Head = NULL;
    Header->Tail = NULL;
    Header->Count = 0;
}

// Flush the content of a double linked list
//
void FlushDList( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return;

    PDLIST_ENTRY head = Header->Head;
    if ( head == NULL )
        return;

    PDLIST_ENTRY current = head;
    while ( current != NULL ) {
        PDLIST_ENTRY next = current->Next;
        free( current );
        current = next;
    }

    // Reset header
    //
    InitializeDListHeader( Header );
}

// Get the head (first element) of a double linked list
//
PDLIST_ENTRY GetDListHead( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return NULL;

    return Header->Head;
}

// Get the tail (last element) of a double linked list
//
PDLIST_ENTRY GetDListTail( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return NULL;

    return Header->Tail;
}

// Get the number of elements
//
size_t GetDListCount( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return 0;

    return Header->Count;
}

// Push an element in front (start) of the list
//
PDLIST_ENTRY PushFrontDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Entry ) {
    if ( Header == NULL )
        return NULL;

    PDLIST_ENTRY head = GetDListHead( Header );
    if ( head != NULL ) {
        head->Prev = Entry;
        Entry->Next = head;
    }

    Entry->Prev = NULL;
    Header->Head = Entry;

    if ( head == NULL )
        Header->Tail = Entry;

    Header->Count++;

    return head;
}

// Push an element in back (end) of the list
//
PDLIST_ENTRY PushBackDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Entry ) {
    if ( Header == NULL )
        return NULL;

    PDLIST_ENTRY tail = GetDListTail( Header );
    if ( tail == NULL )
        return PushFrontDListEntry( Header, Entry );

    Entry->Next = NULL;
    Entry->Prev = tail;
    tail->Next = Entry;

    Header->Tail = Entry;

    Header->Count++;

    return tail;
}

// Insert an element before the specified item
//
PDLIST_ENTRY InsertBeforeDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item, PDLIST_ENTRY Entry ) {
    if ( Header == NULL )
        return NULL;

    if ( Item == NULL )
        return NULL;

    if ( Item == Header->Head )
        return PushFrontDListEntry( Header, Entry );

    PDLIST_ENTRY prev = Item->Prev;

    // prev <-> Entry (new) <-> Item
    //
    Entry->Prev = prev;
    Entry->Next = Item;

    Item->Prev = Entry;
    prev->Next = Entry;

    Header->Count++;

    return Item;
}

// Insert an element after the specified item
//
PDLIST_ENTRY InsertAfterDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item, PDLIST_ENTRY Entry ) {
    if ( Header == NULL )
        return NULL;

    if ( Item == NULL )
        return NULL;

    if ( Item == Header->Tail )
        return PushBackDListEntry( Header, Entry );

    PDLIST_ENTRY next = Item->Next;

    // Item <-> Entry (new) <-> next
    //
    Entry->Prev = Item;
    Entry->Next = next;

    Item->Next = Entry;
    next->Prev = Entry;

    Header->Count++;

    return Item;
}

// Remove an element from the head (start) of the list
//
PDLIST_ENTRY PopFrontDListEntry( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return NULL;

    PDLIST_ENTRY head = Header->Head;
    if ( head == NULL )
        return NULL;

    PDLIST_ENTRY newHead = head->Next;
    newHead->Prev = NULL;
    Header->Head = newHead;

    head->Next = NULL;
    head->Prev = NULL;

    Header->Count--;

    return head;
}

// Remove an element from the tail (end) of the list
//
PDLIST_ENTRY PopBackDListEntry( PDLIST_HEADER Header ) {
    if ( Header == NULL )
        return NULL;

    PDLIST_ENTRY tail = Header->Tail;
    if ( tail == NULL )
        return NULL;

    PDLIST_ENTRY newTail = tail->Prev;
    newTail->Next = NULL;
    Header->Tail = newTail;

    tail->Next = NULL;
    tail->Prev = NULL;

    Header->Count--;

    return tail;
}

// Remove an element before the specified item
//
PDLIST_ENTRY RemoveBeforeDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item ) {
    if ( Header == NULL )
        return NULL;

    if ( Item == NULL )
        return NULL;

    if ( Header->Head == Item )
        return NULL;

    PDLIST_ENTRY node = Item->Prev;
    if ( node == NULL )
        return NULL;

    if ( node == Header->Head )
        return PopFrontDListEntry( Header );

    PDLIST_ENTRY before = node->Prev;

    Item->Prev = before;
    if ( before != NULL )
        before->Next = Item;

    node->Prev = NULL;
    node->Next = NULL;

    Header->Count--;

    return node;
}

// Remove an element after the specified item
//
PDLIST_ENTRY RemoveAfterDListEntry( PDLIST_HEADER Header, PDLIST_ENTRY Item ) {
    if ( Header == NULL )
        return NULL;

    if ( Item == NULL )
        return NULL;

    if ( Header->Tail == Item )
        return PopBackDListEntry( Header );

    PDLIST_ENTRY node = Item->Next;
    if ( node == NULL )
        return NULL;

    if ( node == Header->Tail )
        return PopBackDListEntry( Header );

    PDLIST_ENTRY after = node->Next;

    Item->Next = after;
    if ( after != NULL )
        after->Prev = Item;

    node->Prev = NULL;
    node->Next = NULL;

    Header->Count--;

    return node;
}


// Find the entry matching the predicate
//
PDLIST_ENTRY FindDListEntry( PDLIST_HEADER Header, PDLIST_FINDPREDICATE Predicate ) {
    if ( Header == NULL )
        return NULL;

    if ( Predicate == NULL )
        return NULL;

    PDLIST_ENTRY head = GetDListHead( Header );
    if ( head == NULL )
        return NULL;

    PDLIST_ENTRY found = NULL;
    for ( PDLIST_ENTRY current = head; current != NULL; current = current->Next ) {
        if ( Predicate( current ) ) {
            found = current;
            break;
        }
    }

    return found;
}

// Sort the list following the compartor policy
//
void SortDListBy( PDLIST_HEADER Header, PDLIST_COMPARATOR Comparator ) {
    if ( Header == NULL )
        return;

    if ( Comparator == NULL )
        return;

    if ( GetDListCount( Header ) == 0 )
        return;

    size_t count = GetDListCount( Header );
    size_t size = sizeof( PDLIST_ENTRY ) * ( count + 1 );
    PDLIST_ENTRY* ptrs = ( PDLIST_ENTRY* ) malloc( size );
    if ( ptrs == NULL )
        return;

    int i = 0;
    for ( PDLIST_ENTRY current = GetDListHead( Header ); current != NULL; current = current->Next ) {
        ptrs[ i++ ] = current;
    }

    qsort( ptrs, count, sizeof( PDLIST_ENTRY ), ( int( * )( const void*, const void* ) )Comparator );

    InitializeDListHeader( Header );

    for ( int j = 0; j < count; j++ ) {
        PushBackDListEntry( Header, ptrs[ j ] );
    }

    free( ptrs );
}